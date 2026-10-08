# E2E Test — Private npm registry over Azure Private Link for SPCS and SAR builds

**Date:** 2026-10-06
**Snowflake account:** Azure West Europe test account
**Azure:** one resource group (`<rg>`) holding the VM, LB and Private Link Service

## Architecture

```
Snowflake (SPCS job / SAR remote build)
  └─ EAI PRIVATE_NPM_EAI
       └─ NETWORK RULE TYPE=PRIVATE_HOST_PORT  'npm.kk-private.internal:80'
            └─ Snowflake-managed Private Endpoint (SYSTEM$PROVISION_PRIVATELINK_ENDPOINT)
                 └─ Azure Private Link Service  npm-pls   (NAT IP 10.50.2.4)
                      └─ Internal Standard LB  npm-ilb   :80 → :4873
                           └─ VM npm-vm 10.50.1.4 (no public IP, no NAT)
                                └─ Verdaccio, NO uplinks, serves only @kk/hello-private@1.0.0
```

## Results

| # | Test | Expected | Result |
|---|---|---|---|
| 1 | SPCS job: `npm install @kk/hello-private` via private host | Installs and runs | **PASS**: "hello from the PRIVATE registry over Azure Private Link" |
| 2 | SPCS job: `npm install lodash` from registry.npmjs.org | Blocked | **PASS**: network error |
| 3 | SPCS job: public package via private registry | 404 (no uplink) | **PASS** |
| 4 | SPCS job: `curl https://example.com` | Blocked | **PASS** (no connection) |
| 5 | **SAR build** with `build_eai: PRIVATE_NPM_EAI` (`PRIVATE_HOST_PORT`) | Not documented | **PASS**: build DONE, app serving. Verdaccio log shows metadata + tarball GET from 10.50.2.4 (PLS NAT IP) |
| 6 | SAR build pulling lodash from public npm with `ALLOW_NPM_PACKAGE_DOWNLOAD=FALSE` | Fail | **PASS**: `npm error code ENOTFOUND` (getaddrinfo) |
| 7 | Control: same as 6 with the parameter at default (TRUE) | Succeeds | **PASS**: confirms that #6 was blocked by the parameter |

## Findings to feed back into the SAR prep sheet

- **`PRIVATE_HOST_PORT` works for SAR `build_eai`** (Azure, observed). The docs only name `HOST_PORT`, so this is observed but undocumented. Gap #5 becomes "undocumented, works in test"; get PM confirmation before a customer commitment.
- **Exclusivity needs both pieces.**
  - **Network:** `build_eai` to private host, plus `ALLOW_NPM_PACKAGE_DOWNLOAD=FALSE`.
  - **Registry:** no uplinks. Otherwise the private registry proxies public npm and the "only there" control is cosmetic.
- **The private host name is customer-chosen** (`npm.kk-private.internal`). Snowflake resolves it to the private endpoint, and no public DNS is needed.
- **Plain HTTP:80 over Private Link was accepted.** For production, terminate TLS (443) on the VM or an App Gateway with a cert for the private name.
- **No registry auth was tested.** Build-time token supply is still undocumented (gap #6).

## Reproduce

- Azure: `npm_privatelink/cloud-init.yaml`, `setup.sh`, `pub.sh`. The NAT gateway was used only during setup and then removed.
- Snowflake: `npm_privatelink/sf_setup.sql`, `job.sql`, `img/` (test image), `sar_app/` (SAR app, v2 `app.yml`).

## Left running (cost)

- **Azure:** `npm-vm` (B2s), `npm-ilb`, `npm-pls`, VNet in `<rg>`.
- **Snowflake:**
  - compute pool `NPM_PL_POOL` (auto-suspend 600s);
  - app `NPM_PL.T.PL_NPM_DEMO`;
  - EAI `PRIVATE_NPM_EAI`;
  - the private endpoint.
- **Teardown:**
  ```sql
  DROP APPLICATION SERVICE NPM_PL.T.PL_NPM_DEMO;
  DROP COMPUTE POOL NPM_PL_POOL;
  SELECT SYSTEM$DEPROVISION_PRIVATELINK_ENDPOINT('<pls id>');
  DROP INTEGRATION PRIVATE_NPM_EAI;
  DROP DATABASE NPM_PL;
  ```
  ```
  az group delete -n <rg>
  ```
