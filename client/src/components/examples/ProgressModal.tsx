import { useState } from "react";
import { ProgressModal } from "../ProgressModal";
import { Button } from "@/components/ui/button";

export default function ProgressModalExample() {
  const [isOpen, setIsOpen] = useState(true);

  return (
    <div className="p-6">
      <Button onClick={() => setIsOpen(true)}>Open Progress Modal</Button>
      <ProgressModal
        isOpen={isOpen}
        onClose={() => setIsOpen(false)}
        assetId="web-api-gateway"
        evaluationId="aev-001"
      />
    </div>
  );
}
