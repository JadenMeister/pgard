import type { DeviceCodeInfo } from "../../../shared/api-types";
import { useI18n } from "../../i18n/I18nProvider";
import { formatExpiry, isGitHubUrl } from "./device-code";

/** GitHub device-flow instructions, shown by both the authorization and the scan panels. */
export function DeviceCodeNotice({ deviceCode }: { deviceCode: DeviceCodeInfo }) {
  const { m } = useI18n();
  return (
    <div className="device-code" role="status">
      <p>
        {m.deviceCode.required}{" "}
        {isGitHubUrl(deviceCode.verificationUri) ? (
          <a href={deviceCode.verificationUri} target="_blank" rel="noreferrer noopener">
            {deviceCode.verificationUri}
          </a>
        ) : (
          <code>{deviceCode.verificationUri}</code>
        )}{" "}
        {m.deviceCode.enterCode}
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
            {m.deviceCode.openButton}
          </a>
        </p>
      )}
      <p className="muted">{formatExpiry(deviceCode.expiresIn, m)}</p>
    </div>
  );
}
