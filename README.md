# Gatelock

Gatelock is a lightweight Role-Based Access Control (RBAC) library for JavaScript applications. It provides a flexible way to define and enforce granular permissions using a structured string syntax, allowing you to configure custom subject types (e.g., `admin`, `guest`) and resource types (e.g., `orders`, `products`) to fit any API. It's heavily inspired by the FHIR scope and launch context spec.

## Usage

```typescript
import { PermissionChecker } from "./gatelock";

const appSubjects = ["student", "instructor"] as const;
const appResources = ["students", "orders", "chats", "docs"] as const;

const studentGrantedPermissions: string[] = [
  "student/docs.r", // Read any document
  "student/orders.c", // Create new orders
  "student/orders.u?id=101", // Update specific order '101'
  "student/chats.r?roomId=34", // Read specific chat room '34'
];

const checker = new PermissionChecker(
  studentGrantedPermissions,
  appSubjects,
  appResources,
);

checker.can("student/docs.r"); // true
checker.can("student/orders.c"); // true
checker.can("student/orders.u?id=101"); // true
checker.can("student/orders.u?id=202"); // false
checker.can("student/chats.r?roomId=34"); // true
checker.can("student/chats.r?roomId=183"); // false
```

## License

This project is licensed under the MIT License.
