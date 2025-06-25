import * as assert from "node:assert";
import { describe, test } from "node:test";

import {
  parsePermissionScope,
  PermissionChecker,
  PermissionScope,
} from "./gatelock";

const testSubjects = ["user", "admin", "guest", "service"] as const;
type TestSubjectType = (typeof testSubjects)[number];

const testResources = [
  "products",
  "orders",
  "users",
  "invoices",
  "reports",
] as const;
type TestResourceType = (typeof testResources)[number];

describe("parsePermissionScope", () => {
  test("should correctly parse a basic scope string", () => {
    const scope = parsePermissionScope<TestSubjectType, TestResourceType>(
      "user/products.r",
      testSubjects,
      testResources,
    );
    assert.deepStrictEqual(scope, {
      subject: "user",
      resourceType: "products",
      actions: ["r"],
      parameters: undefined,
    });
  });

  test("should correctly parse a scope string with multiple actions", () => {
    const scope = parsePermissionScope<TestSubjectType, TestResourceType>(
      "admin/users.cud",
      testSubjects,
      testResources,
    );
    assert.deepStrictEqual(scope, {
      subject: "admin",
      resourceType: "users",
      actions: ["c", "u", "d"],
      parameters: undefined,
    });
  });

  test("should correctly parse a scope string with wildcard resource", () => {
    const scope = parsePermissionScope<TestSubjectType, TestResourceType>(
      "service/*.crs",
      testSubjects,
      testResources,
    );
    assert.deepStrictEqual(scope, {
      subject: "service",
      resourceType: "*",
      actions: ["c", "r", "s"],
      parameters: undefined,
    });
  });

  test("should correctly parse a scope string with parameters", () => {
    const scope = parsePermissionScope<TestSubjectType, TestResourceType>(
      "user/orders.r?status=pending&userId=abc",
      testSubjects,
      testResources,
    );
    assert.deepStrictEqual(scope, {
      subject: "user",
      resourceType: "orders",
      actions: ["r"],
      parameters: { status: "pending", userId: "abc" },
    });
  });

  test("should return null for invalid scope string format", () => {
    assert.strictEqual(
      parsePermissionScope<TestSubjectType, TestResourceType>(
        "user.r",
        testSubjects,
        testResources,
      ),
      null,
    );
    assert.strictEqual(
      parsePermissionScope<TestSubjectType, TestResourceType>(
        "admin/",
        testSubjects,
        testResources,
      ),
      null,
    );
    assert.strictEqual(
      parsePermissionScope<TestSubjectType, TestResourceType>(
        "guest/reports",
        testSubjects,
        testResources,
      ),
      null,
    );
  });

  test("should return null for invalid subject when validSubjects are provided", () => {
    assert.strictEqual(
      parsePermissionScope<TestSubjectType, TestResourceType>(
        "unknown/products.r",
        testSubjects,
        testResources,
      ),
      null,
    );
  });

  test("should return null for invalid resource type when validResources are provided", () => {
    assert.strictEqual(
      parsePermissionScope<TestSubjectType, TestResourceType>(
        "user/nonexistent.r",
        testSubjects,
        testResources,
      ),
      null,
    );
  });

  test("should return null for invalid actions", () => {
    assert.strictEqual(
      parsePermissionScope<TestSubjectType, TestResourceType>(
        "user/products.x",
        testSubjects,
        testResources,
      ),
      null,
    );
    assert.strictEqual(
      parsePermissionScope<TestSubjectType, TestResourceType>(
        "admin/users.c_r",
        testSubjects,
        testResources,
      ),
      null,
    );
  });
});

describe("PermissionChecker", () => {
  const commonGrantedScopes: string[] = [
    "user/products.r",
    "admin/users.crud",
    "service/*.c",
    "user/orders.r?userId=currentuser123",
    "admin/reports.r?department=sales&region=east",
  ];

  const checker = new PermissionChecker<TestSubjectType, TestResourceType>(
    commonGrantedScopes,
    testSubjects,
    testResources,
  );

  test("should grant access for an exact match", () => {
    assert.strictEqual(checker.can("user/products.r"), true);
  });

  test("should grant access for wildcard resource type from granted scope", () => {
    assert.strictEqual(checker.can("service/invoices.c"), true);
    assert.strictEqual(checker.can("service/users.c"), true);
  });

  test("should deny access if subject does not match", () => {
    assert.strictEqual(checker.can("admin/products.r"), false);
  });

  test("should deny access if resource type does not match (and not wildcard)", () => {
    assert.strictEqual(checker.can("user/invoices.r"), false);
  });

  test("should deny access if action is not granted", () => {
    assert.strictEqual(checker.can("user/products.c"), false);
    assert.strictEqual(checker.can("admin/users.s"), false);
  });

  test("should grant access if requested actions are a subset of granted actions", () => {
    assert.strictEqual(checker.can("admin/users.r"), true);
    assert.strictEqual(checker.can("admin/users.cu"), true);
  });

  test("should handle parameter matching correctly (exact match required)", () => {
    assert.strictEqual(
      checker.can("user/orders.r?userId=currentuser123"),
      true,
    );
    assert.strictEqual(checker.can("user/orders.r?userId=anotheruser"), false);
    assert.strictEqual(checker.can("user/orders.r"), false);
  });

  test("should handle multiple parameter matching (exact match required)", () => {
    assert.strictEqual(
      checker.can("admin/reports.r?department=sales&region=east"),
      true,
    );
    assert.strictEqual(checker.can("admin/reports.r?department=sales"), false);
    assert.strictEqual(checker.can("admin/reports.r?region=east"), false);
    assert.strictEqual(
      checker.can("admin/reports.r?department=marketing&region=east"),
      false,
    );
  });

  test("should filter out invalid scopes provided in the constructor", () => {
    const lenientChecker = new PermissionChecker<
      TestSubjectType,
      TestResourceType
    >(
      [
        "user/products.r",
        "invalid-scope-format",
        "unknown_subject/resource.r",
        "user/unknown_resource.r",
      ],
      testSubjects,
      testResources,
    );
    const expectedScopes: Array<
      PermissionScope<TestSubjectType, TestResourceType>
    > = [
      {
        subject: "user",
        resourceType: "products",
        actions: ["r"],
        parameters: undefined,
      },
    ];

    assert.deepStrictEqual(
      (lenientChecker as any)["grantedScopes"],
      expectedScopes,
    );
  });

  test("should return false if requested scope is invalid", () => {
    assert.strictEqual(checker.can("invalid-request"), false);
    assert.strictEqual(checker.can("user/products.xyz"), false);
  });
});
