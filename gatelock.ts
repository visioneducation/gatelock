export type SubjectType<S extends string> = S;

export type Action = "c" | "r" | "u" | "d" | "s";

export type Actions = Action[];

export interface PermissionParameters {
  [key: string]: string | number | boolean;
}

export type ResourceType<R extends string> = R | "*";

export interface PermissionScope<S extends string, R extends string> {
  subject: SubjectType<S>;
  resourceType: ResourceType<R>;
  actions: Actions;
  parameters?: PermissionParameters;
}

export function parsePermissionScope<S extends string, R extends string>(
  scopeString: string,
  validSubjects?: readonly S[],
  validResources?: readonly R[],
): PermissionScope<S, R> | null {
  const parts = scopeString.split(/[\/\.\?]/);

  if (parts.length < 3) {
    return null;
  }

  const rawSubject = parts[0];
  const rawResourceType = parts[1];
  const actions = parts[2].split("") as Action[];

  if (validSubjects && !validSubjects.includes(rawSubject as S)) {
    return null;
  }
  const subject: SubjectType<S> = rawSubject as SubjectType<S>;

  if (
    validResources &&
    rawResourceType !== "*" &&
    !validResources.includes(rawResourceType as R)
  ) {
    return null;
  }
  const resourceType: ResourceType<R> = rawResourceType as ResourceType<R>;

  const allValidActions: Action[] = ["c", "r", "u", "d", "s"];
  if (!actions.every((action) => allValidActions.includes(action))) {
    return null;
  }

  let parameters: PermissionParameters | undefined;

  if (scopeString.includes("?")) {
    const paramString = scopeString.split("?")[1];
    parameters = {};
    paramString.split("&").forEach((param) => {
      const [key, value] = param.split("=");
      if (key && value) {
        parameters![key] = value;
      }
    });
  }

  return { subject, resourceType, actions, parameters };
}

export class PermissionChecker<S extends string, R extends string> {
  private grantedScopes: Array<PermissionScope<S, R>>;
  private validSubjects: readonly S[] | undefined;
  private validResources: readonly R[] | undefined;

  constructor(
    scopes: string[],
    validSubjects?: readonly S[],
    validResources?: readonly R[],
  ) {
    this.validSubjects = validSubjects;
    this.validResources = validResources;
    this.grantedScopes = scopes
      .map((s) => parsePermissionScope<S, R>(s, validSubjects, validResources))
      .filter((s): s is PermissionScope<S, R> => s !== null);
  }

  can(requestedScope: string, context?: { [key: string]: any }): boolean {
    const reqPerm = parsePermissionScope<S, R>(
      requestedScope,
      this.validSubjects,
      this.validResources,
    );
    if (!reqPerm) {
      return false;
    }

    for (const grantedPerm of this.grantedScopes) {
      if (grantedPerm.subject !== reqPerm.subject) {
        continue;
      }

      if (
        grantedPerm.resourceType !== "*" &&
        grantedPerm.resourceType !== reqPerm.resourceType
      ) {
        continue;
      }

      const hasAllRequestedActions = reqPerm.actions.every((action) =>
        grantedPerm.actions.includes(action),
      );
      if (!hasAllRequestedActions) {
        continue;
      }

      let paramsMatch = true;

      if (grantedPerm.parameters) {
        for (const grantedKey in grantedPerm.parameters) {
          const grantedValue = grantedPerm.parameters[grantedKey];

          if (
            !reqPerm.parameters ||
            reqPerm.parameters[grantedKey] === undefined ||
            reqPerm.parameters[grantedKey] !== grantedValue
          ) {
            paramsMatch = false;
            break;
          }
        }
      }

      if (reqPerm.parameters && !grantedPerm.parameters) {
        paramsMatch = false;
      }

      if (!paramsMatch) {
        continue;
      }
      return true;
    }
    return false;
  }
}
