# PGARD 릴리스 절차

> [English](RELEASING.md)가 기준 문서이며 이 문서는 그 번역입니다.

PGARD는 npm 패키지 `pgard` 하나로 배포됩니다(`npm run pack:pgard`가 `packaging/pgard/package.json`으로 빌드). 릴리스는 버전 태그입니다. [`release` 워크플로](../.github/workflows/release.yml)가 검증하고, 사람의 승인을 기다린 뒤, 검증된 tarball을 provenance와 함께 npm에 배포합니다. Homebrew는 배포된 tarball을 바탕으로 갱신합니다.

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
2. **npm trusted publisher.** npm 이름 `pgard`는 이미 자리 표시용 패키지(0.0.1)가 선점하고 있으므로 존재하며 설정할 수 있습니다. npmjs.com에서 패키지, Settings, Trusted Publisher, GitHub Actions를 열고 owner `JadenMeister`, repository `pgard`, workflow 파일명 `release.yml`(경로 없이 파일명만), environment `npm-publish`를 입력합니다. 모든 값은 대소문자를 구분하며 npm은 저장할 때 검증하지 않으므로 오류는 배포 시점에야 나타납니다. 새 설정은 2일 안에 첫 배포가 성공하지 않으면 만료됩니다. 참고: [npm trusted publishing](https://docs.npmjs.com/trusted-publishers).
3. **Homebrew tap**(첫 배포 후): [packaging/homebrew/README.md](../packaging/homebrew/README.md)를 보세요.

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
6. **드라이런(권장).** Actions, `release`, Run workflow에서 `main`을 고르고 버전을 입력하고 `dry_run`을 켭니다. 모든 검증과 `npm publish --dry-run`을 실행하며 아무것도 배포되지 않습니다.
7. **태그.** `main`의 머지된 커밋에서 `git tag -a vX.Y.Z -m "pgard X.Y.Z"`, `git push origin vX.Y.Z`. 태그는 `v` + 정확한 버전(`v0.1.0`, `v0.2.0-rc.1`)이며, 패키지 버전과 다르면 워크플로가 거부합니다.
8. **승인.** `verify` 작업이 빌드, 검사를 실행하고 tarball을 올립니다. 이어서 `publish` 작업이 `npm-publish` 환경에서 대기합니다. 필수 검토자가 실행 화면에서 태그, 커밋, verify 결과가 의도한 것인지 확인하고 승인합니다. 배포 작업은 tarball 체크섬을 verify 작업의 값과 대조한 뒤 `npm publish <tarball> --provenance --access public`을 실행합니다.
9. **배포 후 확인**(아래).
10. **GitHub 릴리스.** 태그에 대한 GitHub 릴리스를 변경 기록 해당 절을 노트로 직접 만듭니다.
11. **Homebrew.** tap을 갱신합니다([packaging/homebrew/README.md](../packaging/homebrew/README.md)).

## 배포 후 확인

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

그다음 정상 체크리스트로 패치 릴리스(`X.Y.Z+1`)를 내어 앞으로 고칩니다. `latest`가 나쁜 버전을 가리켜 이전의 좋은 버전을 먼저 복원해야 한다면 `npm dist-tag add pgard@<좋은 버전> latest`로 되돌립니다(배포 권한이 있는 관리자 로그인 필요). 비밀 값 유출이나 보안 문제라면 deprecate하고, 수정 버전을 내고, 변경 기록의 Security에 밝힙니다. Homebrew tap은 수정된 버전으로 갱신하거나 마지막 커밋을 되돌립니다.
