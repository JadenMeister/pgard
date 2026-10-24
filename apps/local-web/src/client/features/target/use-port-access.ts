import { useEffect, useRef, useState } from "react";
import type { AuthStatus } from "../../../shared/api-types";
import { PortAccessController, type PortAccessHandlers } from "./port-access";

/**
 * Runs a `PortAccessController` for the target panel: every new authorization status goes through
 * `update`, which sends port requests only once access opens. The handlers may change on each
 * render; the latest ones are used.
 */
export function usePortAccess(
  auth: AuthStatus | null,
  presetPort: number | null,
  handlers: PortAccessHandlers,
): PortAccessController {
  const handlersRef = useRef(handlers);
  handlersRef.current = handlers;
  const [controller] = useState(
    () =>
      new PortAccessController(presetPort, {
        listPorts: () => handlersRef.current.listPorts(),
        probe: (port) => handlersRef.current.probe(port),
        reset: () => handlersRef.current.reset(),
      }),
  );
  useEffect(() => controller.update(auth), [auth, controller]);
  return controller;
}
