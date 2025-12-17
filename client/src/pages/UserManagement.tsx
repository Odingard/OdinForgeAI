import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useAuth } from "@/contexts/AuthContext";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useToast } from "@/hooks/use-toast";
import { formatDistanceToNow } from "date-fns";
import { roleMetadata, userRoles, type UserRole } from "@shared/schema";
import { 
  Users, 
  UserPlus, 
  Trash2, 
  Edit, 
  Shield,
  ShieldCheck,
  Lock,
  AlertTriangle,
  CheckCircle2
} from "lucide-react";

interface User {
  id: string;
  username: string;
  role: string;
  displayName: string | null;
  email: string | null;
  createdAt: string | null;
  lastLoginAt: string | null;
}

export default function UserManagement() {
  const { toast } = useToast();
  const { hasPermission } = useAuth();
  
  const canManageUsers = hasPermission("org:manage_users");
  const canAssignRoles = hasPermission("org:assign_roles");
  
  const [addDialogOpen, setAddDialogOpen] = useState(false);
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  
  const [newUsername, setNewUsername] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState<string>("security_analyst");
  const [newDisplayName, setNewDisplayName] = useState("");
  const [newEmail, setNewEmail] = useState("");
  
  const [editRole, setEditRole] = useState("");
  const [editDisplayName, setEditDisplayName] = useState("");
  const [editEmail, setEditEmail] = useState("");

  const { data: users = [], isLoading } = useQuery<User[]>({
    queryKey: ["/api/users"],
  });

  const assignableRoles = userRoles.filter(
    role => roleMetadata[role]?.customerAssignable
  );

  const getRoleBreakdown = () => {
    const breakdown: Record<string, number> = {};
    users.forEach(user => {
      breakdown[user.role] = (breakdown[user.role] || 0) + 1;
    });
    return breakdown;
  };

  const roleBreakdown = getRoleBreakdown();

  const createUserMutation = useMutation({
    mutationFn: async (data: { username: string; password: string; role: string; displayName?: string; email?: string }) => {
      const response = await apiRequest("POST", "/api/users", data);
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "User Created",
        description: "The new user has been created successfully.",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/users"] });
      setAddDialogOpen(false);
      resetAddForm();
    },
    onError: (error: Error) => {
      toast({
        title: "Failed to Create User",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const updateUserMutation = useMutation({
    mutationFn: async ({ id, updates }: { id: string; updates: Partial<User> }) => {
      const response = await apiRequest("PATCH", `/api/users/${id}`, updates);
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "User Updated",
        description: "The user has been updated successfully.",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/users"] });
      setEditDialogOpen(false);
      setSelectedUser(null);
    },
    onError: (error: Error) => {
      toast({
        title: "Failed to Update User",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const deleteUserMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/users/${id}`);
    },
    onSuccess: () => {
      toast({
        title: "User Deleted",
        description: "The user has been removed.",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/users"] });
      setDeleteDialogOpen(false);
      setSelectedUser(null);
    },
    onError: (error: Error) => {
      toast({
        title: "Failed to Delete User",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const resetAddForm = () => {
    setNewUsername("");
    setNewPassword("");
    setNewRole("security_analyst");
    setNewDisplayName("");
    setNewEmail("");
  };

  const handleCreate = () => {
    if (!newUsername.trim() || !newPassword.trim()) {
      toast({
        title: "Error",
        description: "Username and password are required",
        variant: "destructive",
      });
      return;
    }
    createUserMutation.mutate({
      username: newUsername,
      password: newPassword,
      role: newRole,
      displayName: newDisplayName || undefined,
      email: newEmail || undefined,
    });
  };

  const handleEdit = (user: User) => {
    setSelectedUser(user);
    setEditRole(user.role);
    setEditDisplayName(user.displayName || "");
    setEditEmail(user.email || "");
    setEditDialogOpen(true);
  };

  const handleUpdate = () => {
    if (!selectedUser) return;
    updateUserMutation.mutate({
      id: selectedUser.id,
      updates: {
        role: editRole,
        displayName: editDisplayName || null,
        email: editEmail || null,
      },
    });
  };

  const handleDelete = (user: User) => {
    setSelectedUser(user);
    setDeleteDialogOpen(true);
  };

  const confirmDelete = () => {
    if (!selectedUser) return;
    deleteUserMutation.mutate(selectedUser.id);
  };

  const getRoleBadgeVariant = (role: string): "default" | "secondary" | "destructive" | "outline" => {
    const meta = roleMetadata[role as UserRole];
    if (!meta) return "outline";
    if (meta.category === "platform") return "destructive";
    if (meta.category === "organization") return "default";
    if (meta.category === "specialized") return "secondary";
    return "outline";
  };

  if (!canManageUsers) {
    return (
      <div className="space-y-6 p-6">
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            You do not have permission to manage users. Contact your administrator for access.
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold" data-testid="text-page-title">User Management</h1>
          <p className="text-muted-foreground">
            Manage platform users and their access permissions
          </p>
        </div>
        <Dialog open={addDialogOpen} onOpenChange={(open) => {
          setAddDialogOpen(open);
          if (!open) resetAddForm();
        }}>
          <DialogTrigger asChild>
            <Button data-testid="btn-add-user" disabled={!canManageUsers}>
              {canManageUsers ? <UserPlus className="h-4 w-4 mr-2" /> : <Lock className="h-4 w-4 mr-2" />}
              Add User
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Add New User</DialogTitle>
              <DialogDescription>
                Create a new user account with assigned role
              </DialogDescription>
            </DialogHeader>
            
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="username">Username</Label>
                <Input
                  id="username"
                  placeholder="e.g., john.doe"
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  data-testid="input-username"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  placeholder="Enter password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  data-testid="input-password"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="displayName">Display Name</Label>
                <Input
                  id="displayName"
                  placeholder="e.g., John Doe"
                  value={newDisplayName}
                  onChange={(e) => setNewDisplayName(e.target.value)}
                  data-testid="input-display-name"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  type="email"
                  placeholder="e.g., john.doe@example.com"
                  value={newEmail}
                  onChange={(e) => setNewEmail(e.target.value)}
                  data-testid="input-email"
                />
              </div>
              <div className="space-y-2">
                <Label>Role</Label>
                <Select value={newRole} onValueChange={setNewRole}>
                  <SelectTrigger data-testid="select-role">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {assignableRoles.map(role => (
                      <SelectItem key={role} value={role}>
                        {roleMetadata[role]?.displayName || role}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {roleMetadata[newRole as UserRole] && (
                  <p className="text-xs text-muted-foreground mt-1">
                    {roleMetadata[newRole as UserRole].description}
                  </p>
                )}
              </div>
              <Button 
                className="w-full" 
                onClick={handleCreate}
                disabled={createUserMutation.isPending}
                data-testid="btn-submit-create"
              >
                {createUserMutation.isPending ? "Creating..." : "Create User"}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Users</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="text-total-users">
              {users.length}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Administrators</CardTitle>
            <ShieldCheck className="h-4 w-4 text-cyan-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-cyan-600" data-testid="text-admin-count">
              {(roleBreakdown["organization_owner"] || 0) + (roleBreakdown["security_administrator"] || 0)}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Engineers</CardTitle>
            <Shield className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-blue-600" data-testid="text-engineer-count">
              {roleBreakdown["security_engineer"] || 0}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Analysts & Viewers</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="text-viewer-count">
              {(roleBreakdown["security_analyst"] || 0) + (roleBreakdown["executive_viewer"] || 0) + (roleBreakdown["compliance_officer"] || 0)}
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Users</CardTitle>
          <CardDescription>
            All users with access to the OdinForge platform
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="text-center py-8 text-muted-foreground">Loading users...</div>
          ) : users.length === 0 ? (
            <div className="text-center py-8">
              <Users className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
              <h3 className="font-medium mb-2">No Users Found</h3>
              <p className="text-muted-foreground text-sm mb-4">
                Add users to give them access to the platform
              </p>
              <Button onClick={() => setAddDialogOpen(true)} data-testid="btn-add-first-user">
                <UserPlus className="h-4 w-4 mr-2" />
                Add First User
              </Button>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>Email</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Last Login</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.map((user) => (
                  <TableRow key={user.id} data-testid={`row-user-${user.id}`}>
                    <TableCell>
                      <div>
                        <div className="font-medium" data-testid={`text-displayname-${user.id}`}>
                          {user.displayName || user.username}
                        </div>
                        <div className="text-sm text-muted-foreground" data-testid={`text-username-${user.id}`}>
                          @{user.username}
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant={getRoleBadgeVariant(user.role)} data-testid={`badge-role-${user.id}`}>
                        {roleMetadata[user.role as UserRole]?.displayName || user.role}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <span className="text-sm" data-testid={`text-email-${user.id}`}>
                        {user.email || "-"}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="text-sm text-muted-foreground" data-testid={`text-created-${user.id}`}>
                        {user.createdAt ? formatDistanceToNow(new Date(user.createdAt), { addSuffix: true }) : "-"}
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="text-sm text-muted-foreground" data-testid={`text-lastlogin-${user.id}`}>
                        {user.lastLoginAt ? formatDistanceToNow(new Date(user.lastLoginAt), { addSuffix: true }) : "Never"}
                      </span>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-2">
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => handleEdit(user)}
                          disabled={!canAssignRoles}
                          data-testid={`btn-edit-${user.id}`}
                        >
                          <Edit className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => handleDelete(user)}
                          disabled={!canManageUsers}
                          data-testid={`btn-delete-${user.id}`}
                        >
                          <Trash2 className="h-4 w-4 text-destructive" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Dialog open={editDialogOpen} onOpenChange={setEditDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit User</DialogTitle>
            <DialogDescription>
              Update user details and role assignment
            </DialogDescription>
          </DialogHeader>
          {selectedUser && (
            <div className="space-y-4">
              <div className="p-4 bg-muted rounded-md">
                <div className="font-medium">{selectedUser.displayName || selectedUser.username}</div>
                <div className="text-sm text-muted-foreground">@{selectedUser.username}</div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="editDisplayName">Display Name</Label>
                <Input
                  id="editDisplayName"
                  value={editDisplayName}
                  onChange={(e) => setEditDisplayName(e.target.value)}
                  data-testid="input-edit-display-name"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="editEmail">Email</Label>
                <Input
                  id="editEmail"
                  type="email"
                  value={editEmail}
                  onChange={(e) => setEditEmail(e.target.value)}
                  data-testid="input-edit-email"
                />
              </div>
              <div className="space-y-2">
                <Label>Role</Label>
                <Select value={editRole} onValueChange={setEditRole}>
                  <SelectTrigger data-testid="select-edit-role">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {assignableRoles.map(role => (
                      <SelectItem key={role} value={role}>
                        {roleMetadata[role]?.displayName || role}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {roleMetadata[editRole as UserRole] && (
                  <p className="text-xs text-muted-foreground mt-1">
                    {roleMetadata[editRole as UserRole].description}
                  </p>
                )}
              </div>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  className="flex-1"
                  onClick={() => setEditDialogOpen(false)}
                  data-testid="btn-cancel-edit"
                >
                  Cancel
                </Button>
                <Button 
                  className="flex-1" 
                  onClick={handleUpdate}
                  disabled={updateUserMutation.isPending}
                  data-testid="btn-submit-edit"
                >
                  {updateUserMutation.isPending ? "Saving..." : "Save Changes"}
                </Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      <Dialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete User</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete this user? This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          {selectedUser && (
            <div className="space-y-4">
              <div className="p-4 bg-destructive/10 border border-destructive/20 rounded-md">
                <div className="flex items-center gap-2 mb-2">
                  <AlertTriangle className="h-5 w-5 text-destructive" />
                  <span className="font-medium">Confirm Deletion</span>
                </div>
                <p className="text-sm">
                  User <strong>{selectedUser.displayName || selectedUser.username}</strong> (@{selectedUser.username}) will be permanently removed.
                </p>
              </div>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  className="flex-1"
                  onClick={() => setDeleteDialogOpen(false)}
                  data-testid="btn-cancel-delete"
                >
                  Cancel
                </Button>
                <Button 
                  variant="destructive"
                  className="flex-1" 
                  onClick={confirmDelete}
                  disabled={deleteUserMutation.isPending}
                  data-testid="btn-confirm-delete"
                >
                  {deleteUserMutation.isPending ? "Deleting..." : "Delete User"}
                </Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
