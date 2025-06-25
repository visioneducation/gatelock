# Gatelock

Gatelock is a lightweight Role-Based Access Control (RBAC) library for JavaScript applications. It provides a flexible way to define and enforce granular permissions using a structured string syntax, allowing you to configure custom subject types (e.g., `admin`, `guest`) and resource types (e.g., `orders`, `products`) to fit any API. It's heavily inspired by the FHIR scope and launch context spec.

## Usage

```typescript
import { PermissionChecker } from "gatelock";

const mySubjects = ["user", "service"] as const;
const myResources = ["items", "accounts"] as const;

const grantedPermissions: string[] = ["user/items.r", "service/accounts.c"];

const checker = new PermissionChecker(
  grantedPermissions,
  mySubjects,
  myResources,
);

console.log("Can user read items?", checker.can("user/items.r")); // true
console.log("Can user create items?", checker.can("user/items.c")); // false
```

## License

This project is licensed under the MIT License.
