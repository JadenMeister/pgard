import {
  cancelSearch,
  clearProject,
  confirmCandidate,
  getRecent,
  getScope,
  getSearch,
  removeRecent,
  startSearch,
  toggleRoot,
  type PickerContext,
} from "../picker/service.js";
import type { ApiContext, ApiHandler } from "./api.js";
import { ApiError } from "./api-error.js";

/**
 * The picker routes. Every one is `POST` with a JSON body when it changes state; no route is a
 * `GET` with side effects. In fixed mode (`pgard dashboard`) `create-server.ts` answers
 * `409 fixed_project` for every `/api/picker/*` request before the body is read, so these
 * handlers only ever run in picker mode.
 */

function pickerContext(context: ApiContext): PickerContext {
  return { state: context.state, picker: context.deps.picker, now: context.deps.now };
}

function bodyRecord(body: unknown): Record<string, unknown> {
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    throw new ApiError(400, "bad_request", "Expected a JSON object.");
  }
  return body as Record<string, unknown>;
}

const scope: ApiHandler = async (context) => getScope(pickerContext(context));

const toggle: ApiHandler = async (context, body) => {
  const record = bodyRecord(body);
  return toggleRoot(pickerContext(context), record.rootId, record.enabled);
};

const search: ApiHandler = async (context, body) => {
  const record = bodyRecord(body);
  return startSearch(pickerContext(context), {
    source: record.source,
    name: record.name,
    epoch: record.epoch,
  });
};

const searchStatus: ApiHandler = async (context, _body, query) =>
  getSearch(pickerContext(context), query.get("id") ?? undefined);

const searchCancel: ApiHandler = async (context, body) =>
  cancelSearch(pickerContext(context), bodyRecord(body).searchId);

const recent: ApiHandler = async (context) => getRecent(pickerContext(context));

const recentRemove: ApiHandler = async (context, body) =>
  removeRecent(pickerContext(context), bodyRecord(body).entryId);

const confirm: ApiHandler = async (context, body) => {
  const record = bodyRecord(body);
  return confirmCandidate(pickerContext(context), {
    candidateId: record.candidateId,
    shown: record.shown,
    epoch: record.epoch,
  });
};

const clear: ApiHandler = async (context, body) =>
  clearProject(pickerContext(context), bodyRecord(body).epoch);

export const PICKER_ROUTES: Readonly<Record<string, ApiHandler>> = {
  "GET /api/picker/scope": scope,
  "POST /api/picker/scope/toggle": toggle,
  "POST /api/picker/search": search,
  "GET /api/picker/search": searchStatus,
  "POST /api/picker/search/cancel": searchCancel,
  "GET /api/picker/recent": recent,
  "POST /api/picker/recent/remove": recentRemove,
  "POST /api/picker/confirm": confirm,
  "POST /api/picker/clear": clear,
};
