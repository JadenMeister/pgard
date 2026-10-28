import type { DeviceCodeInfo } from "../../../shared/api-types";
import { ButtonLink } from "../ui/Button";
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
          <ButtonLink
            variant="primary"
            href={deviceCode.verificationUri}
            target="_blank"
            rel="noreferrer noopener"
          >
            {m.deviceCode.openButton}
          </ButtonLink>
        </p>
      )}
      <p className="muted">{formatExpiry(deviceCode.expiresIn, m)}</p>
    </div>
  );
}
