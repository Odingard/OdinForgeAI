import { describe, it, expect } from "vitest";
import { getPermissionsForDbRole, dbRoleToSchemaRole, rolePermissions } from "./schema";

describe("dbRoleToSchemaRole", () => {
  it("maps org_owner to organization_owner", () => {
    expect(dbRoleToSchemaRole["org_owner"]).toBe("organization_owner");
  });

  it("maps security_admin to security_administrator", () => {
    expect(dbRoleToSchemaRole["security_admin"]).toBe("security_administrator");
  });

  it("maps platform_super_admin to itself", () => {
    expect(dbRoleToSchemaRole["platform_super_admin"]).toBe("platform_super_admin");
  });
});

describe("getPermissionsForDbRole", () => {
  it("org_owner gets permissions", () => {
    const perms = getPermissionsForDbRole("org_owner");
    expect(perms.length).toBeGreaterThan(20);
    expect(perms).toContain("evaluations:read");
    expect(perms).toContain("assets:create");
  });

  it("security_analyst gets read-focused permissions", () => {
    const perms = getPermissionsForDbRole("security_analyst");
    expect(perms).toContain("evaluations:read");
    expect(perms).toContain("findings:read");
    expect(perms).not.toContain("evaluations:delete");
    expect(perms).not.toContain("assets:delete");
  });

  it("executive_viewer gets minimal permissions", () => {
    const perms = getPermissionsForDbRole("executive_viewer");
    expect(perms.length).toBeLessThanOrEqual(10);
    expect(perms).toContain("evaluations:read");
    expect(perms).not.toContain("evaluations:create");
  });

  it("platform_super_admin gets ALL permissions", () => {
    const superPerms = getPermissionsForDbRole("platform_super_admin");
    // Should have the most permissions of any role
    const ownerPerms = getPermissionsForDbRole("org_owner");
    expect(superPerms.length).toBeGreaterThanOrEqual(ownerPerms.length);
  });

  it("unknown role returns empty array", () => {
    const perms = getPermissionsForDbRole("nonexistent_role");
    expect(perms).toEqual([]);
  });

  it("automation_account has api:write but limited UI permissions", () => {
    const perms = getPermissionsForDbRole("automation_account");
    expect(perms).toContain("api:write");
    expect(perms).not.toContain("org:manage_users");
  });
});
