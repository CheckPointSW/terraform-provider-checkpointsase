# Terraform Provider Check Point SASE

This provider manages [Check Point Harmony SASE](https://www.checkpoint.com/harmony-sase/)
(formerly Perimeter 81) resources with Terraform. The provider name is
`checkpointsase` and it targets the `/v3` public API.

## Requirements

Terraform 1.3.x
Go 1.19.1 (to build the provider plugin)

## Installation

```shell
make
```

## Usage

```terraform
variable "checkpointsase_api_key" {
  type      = string
  sensitive = true
}

provider "checkpointsase" {
  # Never hardcode the key. Prefer the CHECKPOINT_SASE_API_KEY environment
  # variable, which this argument defaults to, and keep it out of version control.
  api_key = var.checkpointsase_api_key

  # Required for any tenant that is not the US production host — see Run Tests.
  base_url = "https://your-tenant-host/api"
}
```

Both arguments read from the environment when omitted: `api_key` from
`CHECKPOINT_SASE_API_KEY`, and `base_url` from `BASE_URL` (defaulting to the US
endpoint). Supplying them that way is the recommended configuration, because it keeps
the credential out of both the configuration and the state file.

## Run Tests

### Offline tests

The unit and schema tests need no credential and make no network call:

```shell
go test -count=1 -v ./checkpointsase/
```

### Acceptance tests

Acceptance tests create and destroy real objects on a real tenant. They run only
when `TF_ACC=1` is set:

```shell
CHECKPOINT_SASE_API_KEY=XXXXXX \
BASE_URL=https://your-tenant-host/api \
TF_ACC=1 go test -timeout 120m -parallel 10 ./checkpointsase/
```

Replace `XXXXXX` with your API key. Never commit it, and never paste it into a
file in this repo — the environment is the only place it belongs.

#### `BASE_URL` — required for any tenant that is not US production

The provider defaults to `BaseURLUS` when `BASE_URL` is unset. Point it at
anything else and you must set `BASE_URL` explicitly.

**The failure mode is misleading and costs a whole run.** Without `BASE_URL` the
calls go to the US host, which does not have your tenant, and every one fails as:

```
Cannot POST /api/v3/groups
```

That reads like a missing or unimplemented endpoint, and the natural response is
to go looking for the endpoint in the spec. It is not a missing endpoint — it is
a request sent to the wrong host. If a whole domain suddenly 404s with
`Cannot <VERB> /api/...`, check `BASE_URL` before anything else.

#### `CHECKPOINT_SASE_TEST_REGION_ID` — only for tests that provision networks

Set this **only** when running tests that create standard networks or regions.
The identity tests — `checkpointsase_user`, `_group`, `_group_membership`,
`_users`, `_groups` — do not read it and do not need it.

It used to be demanded by the universal pre-check, which made the suite
unrunnable for anyone whose tests never touch a region: all seventeen identity
acceptance tests failed on a variable none of them reads, before the first API
call. The check now lives in `testAccPreCheckRegion`, next to the tests that
actually interpolate the value. Setting it out of habit does no harm, but it is
not a prerequisite, and treating it as one hides which tests genuinely depend on
a region.

Region IDs are **tenant-specific**, so there is no default. List the valid ones
for your tenant with the `checkpointsase_regions` data source or
`GET /v3/networks/standard/harmony-sase-regions`. Note that a standard region ID
is **not** valid as an enhanced network's `harmony_sase_region_id` — enhanced
networks draw from a different catalogue, and those fixtures source a region from
the `checkpointsase_enhanced_regions` data source instead.

`CHECKPOINT_SASE_TEST_REGION_ID_2` is needed only by the tests that exercise two
distinct regions.
