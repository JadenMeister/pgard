import type { DeviceCodeInfo } from "../../../shared/api-types";
import { formatExpiry, isGitHubUrl } from "./device-code";

/** GitHub device-flow instructions, shown by both the authorization and the scan panels. */
export function DeviceCodeNotice({ deviceCode }: { deviceCode: DeviceCodeInfo }) {
  return (
    <div className="device-code" role="status">
      <p>
        GitHub sign-in is required. Open{" "}
        {isGitHubUrl(deviceCode.verificationUri) ? (
          <a href={deviceCode.verificationUri} target="_blank" rel="noreferrer noopener">
            {deviceCode.verificationUri}
          </a>
        ) : (
          <code>{deviceCode.verificationUri}</code>
        )}{" "}
        and enter this code:
      </p>
      <p className="code">{deviceCode.userCode}</p>
      {isGitHubUrl(deviceCode.verificationUri) && (
        <p>
          <a
            className="button primary"
            href={deviceCode.verificationUri}
            target="_blank"
            rel="noreferrer noopener"
          >
            Open the GitHub sign-in page
          </a>
        </p>
      )}
      <p className="muted">{formatExpiry(deviceCode.expiresIn)}</p>
    </div>
  );
}
