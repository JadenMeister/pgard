# PGARD 릴리스 절차

> [English](RELEASING.md)가 기준 문서이며 이 문서는 그 번역입니다.

PGARD는 npm 패키지 `pgard` 하나로 배포됩니다(`npm run pack:pgard`가 `packaging/pgard/package.json`으로 빌드). 릴리스는 버전 태그입니다. [`release` 워크플로](../.github/workflows/release.yml)가 검증하고, 사람의 승인을 기다린 뒤, 검증된 tarball을 provenance와 함께 npm에 배포합니다. Homebrew는 배포된 tarball을 바탕으로 갱신합니다.

## 패키지에 들어가는 것(의존성과 라이선스)

`npm run pack:pgard`는 CLI, 대시보드 서버, 소스 분석 워커와 순수 JavaScript 서드파티 의존성(TypeScript 컴파일러, `pdfkit`과 `fontkit`, `@vue/compiler-sfc`와 `postcss`·`@babel/parser`, 그리고 그 전이 의존성)을 esbuild로 `dist/` 아래 몇 개 파일에 번들합니다. 들어가는 버전은 릴리스 머신에서 `npm ci`가 `package-lock.json`대로 설치한 것이라 tarball을 만드는 시점에 고정됩니다. 그 뒤에 전이 의존성의 악성 패치 릴리스가 올라와도 `pgard`를 설치하는 사람에게는 닿지 않습니다([#358](https://github.com/JadenMeister/pgard/issues/358)).

외부로 남는 것은 두 패키지이며, 발행되는 `package.json`의 `dependencies`는 이 둘뿐이고 둘 다 정확한 버전으로 고정합니다. `@napi-rs/keyring`(네이티브, 플랫폼별 미리 빌드된 바이너리를 npm이 선택 패키지로 설치)과 `web-tree-sitter`(WebAssembly 런타임을 파일 경로로 읽음)입니다. tree-sitter 문법(`.wasm`), PDF 글꼴, 대시보드 클라이언트는 `assets/`로 복사하고 실행 시 고정된 SHA-256과 대조합니다. 워커 진입점(`dist/source-worker.js`)과 선택기의 inspector 자식 프로세스(`dist/inspector.js`)는 별도 진입점입니다. 소스맵은 넣지 않습니다(빌드 머신의 파일 경로와 원본 소스가 담기기 때문). 번들은 minify하지 않아 `dist/`를 검토할 수 있습니다.

다음 중 하나라도 해당하면 pack 단계가 실패하고 아무것도 만들지 않습니다.

- `packaging/pgard/package.json`의 `dependencies`가 워크스페이스의 버전과 같은 두 외부 패키지와 정확히 일치하지 않음
- 번들된 패키지에 라이선스 본문(npm tarball의 `LICENSE`, `COPYING`, `NOTICE`)이 없거나, 라이선스를 선언하지 않았거나, `scripts/pack-licenses.mjs`의 허용 목록(MIT, ISC, BSD-2-Clause, BSD-3-Clause, Apache-2.0, 0BSD, BlueOak-1.0.0, CC0-1.0, Python-2.0, 그리고 허용된 라이선스가 선택을 충족하는 SPDX 식)에 없는 라이선스를 선언함. 카피레프트나 알 수 없는 라이선스는 조용히 번들되지 않으며, 소유자가 판단한 뒤 검토된 변경으로 허용 목록을 늘립니다. tarball에 라이선스 필드나 파일이 없는 패키지는 같은 파일의 `LICENSE_OVERRIDES`에 정확한 버전으로 적어 두며, 그 패키지의 새 버전은 다시 검토할 때까지 실패합니다.
- 번들이 `node:` 내장 모듈도 선언된 의존성도 아닌 것을 import하거나, 검토된 허용 목록(`scripts/pack-lib.mjs`의 `ALLOWED_DYNAMIC_USES`, 항목마다 PGARD에서 실행되지 않는 이유 기재)에 없는 코드에서 계산된 경로로 모듈을 불러옴
- `scripts/pack-pgard.mjs`의 `import.meta.url` 자산 경로 재작성이나 pdfkit, `@vue/compiler-sfc` 패치가 더 이상 정확히 한 번 일치하지 않음(해당 패키지를 올릴 때는 패치를 다시 확인)

발행되는 `NOTICE.md`는 저장소의 `NOTICE.md`에 생성된 "Bundled npm packages" 절을 붙인 것으로, 번들된 모든 패키지의 버전, 라이선스, 라이선스 본문이 들어 있습니다. 실제로 번들에 들어간 파일에서 생성하므로 따로 관리할 필요가 없습니다. 의존성을 올렸다면 `npm run pack:pgard`와 `npm run smoke:pack`을 실행하세요. smoke 테스트는 tarball을 설치해 JavaScript, Vue, Python 프로젝트를 스캔하고 JSON, SARIF, HTML, PDF 출력, `precommit`, 대시보드를 설치된 패키지에서 실행합니다.

분석기 해시(`packages/scan-core/src/analyzer-hash.ts`)는 빌드 때 `scripts/analyzer-hash.mjs`가 소스에서 계산해 상수로 번들에 들어가므로 번들링이 동작을 바꾸지 않습니다. 분석기가 쓰는 파서와 컴파일러의 선언 버전과 해석된 버전도 포함하므로 `package-lock.json`의 의존성 변경은 다음 스캔을 전체 스캔으로 만듭니다.

## 버전 규칙

PGARD는 [유의적 버전(SemVer)](https://semver.org/lang/ko/)을 따릅니다. 버전은 사용자나 스크립트가 의존할 수 있는 모든 것에 적용됩니다. 아래 항목을 기존 사용자나 스크립트가 알아챌 수 있게 바꾸면 **호환성을 깨는 변경**(1.0 이후에는 major 증가)입니다.

- **CLI 명령과 옵션.** 명령이나 옵션의 삭제·이름 변경, 옵션 동작이나 허용 값의 변경, 선택 옵션을 필수로 바꾸는 것. 명령이나 선택 옵션의 추가는 호환성을 깨지 않습니다.
- **JSON 결과 스키마.** 스캔 결과의 `schemaVersion`은 [RESULT_SCHEMA.ko.md](RESULT_SCHEMA.ko.md)를 따릅니다. 스키마 minor 증가(추가·선택 사항만)는 minor 릴리스, 스키마 major 증가(`1.x`에서 `2.0`)는 호환성을 깨는 릴리스입니다.
- **SARIF 출력.** 필드의 삭제·이름 변경, 규칙 id·level·위치·fingerprint 표기 방식의 변경, SARIF 2.1.0을 벗어나는 것. 필드 추가는 호환성을 깨지 않습니다.
- **종료 코드.** 0, 2, 3, 4, 5, 130의 의미 변경, 또는 기존 상황이 다른 코드를 반환하게 되는 것. 이전에 내부 오류였던 상황에 새 코드를 주는 것도 호환성을 깹니다.
- **설정 파일 키.** `pgard.config.json` 키의 삭제·이름 변경·타입 변경, 또는 결과가 달라지도록 기본값을 바꾸는 것. 선택 키 추가는 호환성을 깨지 않습니다.
- 그 밖에 지원하는 Node.js 최소 버전을 패치 수준 이상으로 올리는 것과 운영체제 지원 중단도 호환성을 깹니다.

깨지 않는 변경: 새 규칙과 탐지 결과, 문구, 보고서 레이아웃, 성능, 스캐너 자체 동작의 보안 수정. 새 규칙은 사용자의 탐지 결과를 바꿀 수 있으므로 Added에 적습니다.

**1.0 이전 정책(현재).** 버전이 `0.y.z`인 동안에는 호환성을 깨는 변경이 minor를 올리고(`0.1.0`에서 `0.2.0`) 변경 기록에 **BREAKING**으로 표시합니다. patch 릴리스(`0.1.1`)는 버그만 고치며 호환성을 깨지 않습니다. `1.0.0` 이후에는 일반 규칙을 적용합니다. `1.0.0`은 CLI 옵션, 결과 스키마, SARIF, 종료 코드가 안정적이라고 판단될 때까지 미룹니다.

사전 릴리스 버전(`0.2.0-rc.1`)도 가능합니다. 워크플로는 이를 `latest`가 아니라 npm dist-tag `next`로 배포합니다.

## 최초 1회 설정(저장소 소유자)

아래 설정이 없어도 워크플로를 머지하는 것은 안전합니다("아무것도 설정하지 않았을 때" 참고). 첫 릴리스 전에 다음을 설정하세요.

1. **GitHub 환경.** Settings, Environments, New environment `npm-publish`. **Required reviewers**를 추가하고(본인과 릴리스를 승인할 수 있는 사람), 검토자가 둘 이상일 때만 "Prevent self-review"를 켜며, **Deployment branches and tags**를 `main`과 태그 패턴 `v*.*.*`로 제한합니다. 참고: [Managing environments for deployment](https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-deployments/managing-environments-for-deployment).
2. **npm trusted publisher.** npm 이름 `pgard`는 이미 자리 표시용 패키지(0.0.1)가 선점하고 있으므로 존재하며 설정할 수 있습니다. npmjs.com에서 패키지, Settings, Trusted Publisher, GitHub Actions를 열고 owner `JadenMeister`, repository `pgard`, workflow 파일명 `release.yml`(경로 없이 파일명만), environment `npm-publish`를 입력합니다. **Allowed actions**에서 **npm publish**를 체크하세요. 2026년 9월 3일 이후 만든 설정은 기본적으로 `npm stage publish`만 허용하는데, 워크플로는 직접 `npm publish`를 실행합니다(버전이 공개되기 전에 npm에서 2FA 승인을 한 번 더 받고 싶다면 `npm stage publish`를 쓸 수 있으며, 그 경우 워크플로가 그 명령을 호출하도록 바꿔야 합니다). **environment 칸은 npm이 선택 사항으로 표시하더라도 반드시 채우세요.** 보안 모델이 이 값에 의존합니다. npm은 워크플로 실행의 environment가 일치할 때만 OIDC 토큰을 받아들입니다. 태그의 커밋이 워크플로에서 `environment:`를 지워 승인을 건너뛰더라도, 설정에 environment 이름이 있어야 npm이 그 토큰을 거부합니다. 모든 값은 대소문자를 구분하며 npm은 저장할 때 검증하지 않으므로 오류는 배포 시점에야 나타납니다. 새 설정은 2일 안에 첫 배포가 성공하지 않으면 만료됩니다. 참고: [npm trusted publishing](https://docs.npmjs.com/trusted-publishers).
3. **태그 ruleset.** Settings, Rules, Rulesets에서 `v*` 태그 ruleset을 추가해 이 태그를 만들고 갱신하고 삭제할 수 있는 사람을 제한하고(force push 차단 포함) 관리자만 릴리스를 시작할 수 있게 하세요. 워크플로도 `main`에 없는 커밋은 추가로 거부합니다.
4. **Homebrew tap**(첫 배포 후): [packaging/homebrew/README.md](../packaging/homebrew/README.md)를 보세요.

**토큰 대안.** trusted publishing을 쓸 수 없으면(예: 셀프 호스트 러너) `pgard` 패키지로 한정하고 publish 권한만 가진 granular npm access token을 만들어 `npm-publish` 환경 secret `NPM_TOKEN`에 저장하고, 배포 단계의 `env:`에 `NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}`을 추가합니다. `--provenance`는 유지하세요. 토큰은 오래 유지되는 자격 증명이므로 가능하면 OIDC를 쓰세요.

## 아무것도 설정하지 않았을 때

- 워크플로는 `v*.*.*` 태그와 수동 실행에서만 돌고 브랜치나 풀 리퀘스트에서는 돌지 않으므로, 머지만으로는 아무것도 배포되지 않습니다.
- `npm-publish` 환경이 없으면 GitHub가 첫 실행 때 **보호 규칙 없이 환경을 자동으로 만들고**, 배포 작업은 승인 없이 시작됩니다. 그래서 환경만 믿으면 안 됩니다. 그래도 배포는 실패합니다. npm에 trusted publisher(또는 `NPM_TOKEN`)가 없으면 npm이 OIDC 토큰이나 없는 로그인을 거부해서 아무것도 배포되지 않습니다. provenance에는 공개 저장소와 GitHub 호스트 러너의 `id-token: write`가 필요하며 작업이 이를 갖추고 있습니다.
- 이런 실행도 피하려면 첫 태그를 푸시하기 **전에** 위 설정을 마치고, 먼저 `dry_run`으로 수동 실행하세요.

## 릴리스 체크리스트

1. **초록색 `main`에서 시작합니다.** 릴리스에 들어갈 PR이 모두 머지되고 CI가 통과한 상태여야 합니다.
2. 위 규칙으로 **버전을 정합니다.**
3. 두 곳의 **버전을 올립니다.** 둘은 일치해야 합니다(다르면 pack 단계와 워크플로가 실패합니다).
   - `packaging/pgard/package.json`(`version`)
   - `packages/scan-core/src/version.ts`(`PGARD_VERSION`)
4. **`CHANGELOG.md`를 갱신합니다.** `## [Unreleased]` 내용을 `## [X.Y.Z] - YYYY-MM-DD`로 옮기고 비어 있는 `## [Unreleased]`를 새로 두며 하단 비교 링크를 갱신합니다. 항목은 Added, Changed, Fixed, Security(필요하면 Removed, Deprecated)로 묶고, 호환성을 깨는 변경에는 **BREAKING**을 붙입니다.
5. `chore(release): vX.Y.Z` **PR**을 이 변경만으로 열고 리뷰한 뒤 머지합니다. 그 전에 로컬에서 `npm run check`, `npm run corpus:check`, `npm run pack:pgard`, `npm run smoke:pack`을 실행합니다.
6. **드라이런(권장).** Actions, `release`, Run workflow에서 `main`을 고르고 버전을 입력하고 `dry_run`을 켭니다. 모든 검증과 `npm publish --dry-run`을 실행하며 아무것도 배포되지 않습니다. 드라이런도 `publish` 작업을 거치므로 **`npm-publish` 승인을 기다리고 OIDC 토큰도 요청합니다.** 브랜치에서의 수동 실행은 드라이런만 가능하며 실제 배포에는 태그가 필요합니다.
7. **태그.** `main`의 머지된 커밋에서 `git tag -a vX.Y.Z -m "pgard X.Y.Z"`, `git push origin vX.Y.Z`. 태그는 `v` + 정확한 버전(`v0.1.0`, `v0.2.0-rc.1`)이며, 패키지 버전과 다르면 워크플로가 거부합니다.
8. **승인.** `verify` 작업이 빌드, 검사를 실행하고 tarball을 올립니다. 이어서 `publish` 작업이 `npm-publish` 환경에서 대기합니다. 필수 검토자가 실행 화면에서 태그, 커밋, verify 결과가 의도한 것인지 확인하고 승인합니다. 배포 작업은 tarball 체크섬을 verify 작업의 값과 대조한 뒤 `npm publish <tarball> --provenance --access public`을 실행합니다.
9. **배포 후 확인**(아래).
10. **GitHub 릴리스.** 태그에 대한 GitHub 릴리스를 변경 기록 해당 절을 노트로 직접 만듭니다.
11. **Homebrew.** tap을 갱신합니다([packaging/homebrew/README.md](../packaging/homebrew/README.md)).

## 배포 후 확인

레지스트리가 보고하는 값만이 아니라 릴리스 실행이 만든 tarball이 맞는지도 확인하려면 `packaging/homebrew/update-formula.sh X.Y.Z`를 쓰세요. formula를 고치기 전에 내려받은 tarball을 출처 증명(provenance)의 subject digest와 대조하고 `gh attestation verify`를 실행합니다. `verify` 작업이 실행 요약에 출력하는 sha256은 `EXPECTED_SHA256=<hex>`로 넘기면 함께 비교합니다.

```sh
npm view pgard@X.Y.Z version dist.tarball dist.integrity
npm view pgard dist-tags              # latest는 X.Y.Z여야 함(사전 릴리스는 next)
```

- `https://www.npmjs.com/package/pgard/v/X.Y.Z`를 열어 **Provenance** 배지가 `JadenMeister/pgard` 저장소, `release.yml` 워크플로, 태그의 커밋을 가리키는지 확인합니다. 이 패키지에 의존하는 프로젝트에서 `npm audit signatures`를 실행하면 레지스트리 서명과 attestation을 검증합니다.
- 임시 prefix에 설치해 확인합니다(전역 설치 없음).

  ```sh
  prefix="$(mktemp -d)"
  npm install --prefix "$prefix" pgard@X.Y.Z
  "$prefix/node_modules/.bin/pgard" --version      # pgard X.Y.Z
  "$prefix/node_modules/.bin/pgard" doctor
  rm -rf "$prefix"
  ```

- 빈 디렉터리에서 `npx pgard@X.Y.Z --version`이 동작하는지 확인합니다.

## 롤백

배포된 버전은 교체할 수 없고 `npm unpublish`는 쓰지 않습니다(그 버전에 의존하는 모두를 깨뜨리며 npm도 제한합니다). 대신 다음을 실행합니다.

```sh
npm deprecate pgard@X.Y.Z "Broken: use X.Y.Z+1 (reason: ...)"
```

`npm deprecate`와 `npm dist-tag`는 OIDC 배포 설정으로 처리되지 않습니다. 관리자가 로컬에서 대화형 `npm login`(2FA 포함) 후 실행합니다.

그다음 정상 체크리스트로 패치 릴리스(`X.Y.Z+1`)를 내어 앞으로 고칩니다. `latest`가 나쁜 버전을 가리켜 이전의 좋은 버전을 먼저 복원해야 한다면 `npm dist-tag add pgard@<좋은 버전> latest`로 되돌립니다(배포 권한이 있는 관리자 로그인 필요. npm CLI 11.21.0 이상에서는 해당 권한을 체크한 경우 trusted publisher도 dist-tag를 관리할 수 있습니다). 비밀 값 유출이나 보안 문제라면 deprecate하고, 수정 버전을 내고, 변경 기록의 Security에 밝힙니다. Homebrew tap은 수정된 버전으로 갱신하거나 마지막 커밋을 되돌립니다.
