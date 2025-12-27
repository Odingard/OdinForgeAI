package queue

import (
        "bytes"
        "encoding/binary"
        "encoding/json"
        "errors"
        "time"

        "odinforge-agent/internal/collector"

        bolt "go.etcd.io/bbolt"
)

var (
        bucketEvents = []byte("events")
        keySeq       = []byte("seq")
)

type BoltQueue struct {
        db        *bolt.DB
        maxEvents int
}

func NewBoltQueue(path string, maxEvents int) (*BoltQueue, error) {
        db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 1 * time.Second})
        if err != nil {
                return nil, err
        }
        q := &BoltQueue{db: db, maxEvents: maxEvents}
        err = db.Update(func(tx *bolt.Tx) error {
                _, e := tx.CreateBucketIfNotExists(bucketEvents)
                return e
        })
        if err != nil {
                _ = db.Close()
                return nil, err
        }
        return q, nil
}

func (q *BoltQueue) Close() error { return q.db.Close() }

func (q *BoltQueue) Enqueue(ev collector.Event) error {
        return q.db.Update(func(tx *bolt.Tx) error {
                b := tx.Bucket(bucketEvents)
                if b == nil {
                        return errors.New("events bucket missing")
                }

                // enforce max size: drop oldest if needed
                if q.maxEvents > 0 && b.Stats().KeyN >= q.maxEvents {
                        c := b.Cursor()
                        k, _ := c.First()
                        if k != nil {
                                _ = b.Delete(k)
                        }
                }

                seq := nextSeq(b)
                key := itob(seq)
                data, _ := json.Marshal(ev)
                return b.Put(key, data)
        })
}

func (q *BoltQueue) DequeueBatch(n int) ([]QueuedItem, error) {
        items := make([]QueuedItem, 0, n)
        err := q.db.View(func(tx *bolt.Tx) error {
                b := tx.Bucket(bucketEvents)
                if b == nil {
                        return errors.New("events bucket missing")
                }
                c := b.Cursor()
                for k, v := c.First(); k != nil && len(items) < n; k, v = c.Next() {
                        // Skip the internal sequence key - it's not an event
                        if bytes.Equal(k, keySeq) {
                                continue
                        }
                        items = append(items, QueuedItem{Key: append([]byte(nil), k...), Val: append([]byte(nil), v...)})
                }
                return nil
        })
        return items, err
}

func (q *BoltQueue) Ack(keys [][]byte) error {
        return q.db.Update(func(tx *bolt.Tx) error {
                b := tx.Bucket(bucketEvents)
                if b == nil {
                        return errors.New("events bucket missing")
                }
                for _, k := range keys {
                        _ = b.Delete(k)
                }
                return nil
        })
}

func (q *BoltQueue) Depth() (int, error) {
        depth := 0
        err := q.db.View(func(tx *bolt.Tx) error {
                b := tx.Bucket(bucketEvents)
                if b == nil {
                        return errors.New("events bucket missing")
                }
                // KeyN includes ALL keys, but we have one internal key (keySeq)
                // Subtract 1 if the seq key exists to get actual event count
                keyCount := b.Stats().KeyN
                if b.Get(keySeq) != nil {
                        keyCount--
                }
                if keyCount < 0 {
                        keyCount = 0
                }
                depth = keyCount
                return nil
        })
        return depth, err
}

type QueuedItem struct {
        Key []byte
        Val []byte
}

func nextSeq(b *bolt.Bucket) uint64 {
        v := b.Get(keySeq)
        var seq uint64
        if v != nil {
                seq = binary.BigEndian.Uint64(v)
        }
        seq++
        buf := make([]byte, 8)
        binary.BigEndian.PutUint64(buf, seq)
        _ = b.Put(keySeq, buf)
        return seq
}

func itob(v uint64) []byte {
        var b [8]byte
        binary.BigEndian.PutUint64(b[:], v)
        // avoid lexicographic issues: fixed width big endian keys are ordered
        return b[:]
}

func IsBoltKey(k []byte) bool { return bytes.Equal(k, keySeq) }
