package checkpointsase

import (
	"context"
	"fmt"
	"net/http"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

/*
resourceRegionCreate Create a Region inside a Network
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param networkId string - the network id
  - @param oldRegions []StandardNetworkRegionConfig - the old regions
  - @param newRegions []StandardNetworkRegionConfig - the new regions
  - @param d *schema.ResourceData - the terraform resource data
  - @param client *perimeter81Sdk.APIClient - the api client

@return string, string, error
*/
func resourceRegionCreate(ctx context.Context, networkId string, oldRegions []StandardNetworkRegionConfig, newRegions []StandardNetworkRegionConfig, d *schema.ResourceData, client *perimeter81Sdk.APIClient) (string, string, error) {
	// Get the new regions that need to be created inside a network
	for _, newRegion := range newRegions {
		// If the region does not exist in the old regions, create it
		if !regionExistsInArray(newRegion.CpRegionId, oldRegions) {
			// Create the region inside the network using the standard region payload
			regionPayload := perimeter81Sdk.CreateRegionInNetworkPayload{
				HarmonySaseRegionId: newRegion.CpRegionId,
				Idle:                newRegion.Idle,
			}
			result, _, err := client.StandardRegionsAPI.StandardNetworksControllerV2AddNetworkRegion(ctx, networkId).CreateRegionInNetworkPayload(regionPayload).Execute()
			if err != nil {
				d.Partial(true)
				return "", newRegion.CpRegionId, err
			}
			// AddNetworkRegion returns its AsyncOperationResult inline — there is
			// no status URL to poll — so a non-2xx result.statusCode is the only
			// signal that the add was rejected. Discarding it, as this code used
			// to, meant a rejected add was reported to Terraform as success.
			if !isSuccessStatus(int(result.GetStatusCode())) {
				d.Partial(true)
				return "", newRegion.CpRegionId, &asyncFailedError{StatusCode: int(result.GetStatusCode()), Reasons: result.GetReason()}
			}

			// The add responded 2xx, but the region is not always visible on
			// the network the instant this call returns: it is eventually
			// consistent. resourceNetworkRead re-fetches the network right
			// after this function returns, so wait until the new region is
			// actually present in it — otherwise Read observes stale state.
			displayName, err := regionDisplayNameByCpRegionId(ctx, client, newRegion.CpRegionId)
			if err != nil {
				d.Partial(true)
				return "", newRegion.CpRegionId, err
			}
			what := fmt.Sprintf("region %s to appear in network %s", newRegion.CpRegionId, networkId)
			pollErr := pollUntilConverged(ctx, func(ctx context.Context) (bool, *http.Response, error) {
				network, resp, err := client.StandardNetworksAPI.StandardNetworksControllerV2NetworkFind(ctx, networkId).Execute()
				if err != nil {
					return false, resp, err
				}
				for _, region := range network.Regions {
					if region.Name == displayName {
						return true, resp, nil
					}
				}
				return false, resp, nil
			}, convergencePollInterval, convergenceTransientBudget, what)
			if pollErr != nil {
				d.Partial(true)
				return "", newRegion.CpRegionId, pollErr
			}
		}
	}
	return "", "", nil
}

// regionDisplayNameByCpRegionId resolves a harmony-sase region id (as used in
// CreateRegionInNetworkPayload) to the display name the standard-networks API
// reports back on NetworkRegion.Name. There is no other link between the two:
// setNetworkRegionInfos and importRegions rely on the same display-name match
// to go the other direction.
func regionDisplayNameByCpRegionId(ctx context.Context, client *perimeter81Sdk.APIClient, cpRegionId string) (string, error) {
	regionsData, _, err := client.StandardRegionsAPI.StandardNetworksControllerV2GetRegions(ctx).Execute()
	if err != nil {
		return "", fmt.Errorf("resolving display name for region %s: %w", cpRegionId, err)
	}
	for _, region := range regionsData {
		if region.GetId() == cpRegionId {
			return region.GetDisplayName(), nil
		}
	}
	return "", fmt.Errorf("resolving display name for region %s: not found in the region catalog", cpRegionId)
}

/*
resourceRegionDelete Delete a Region from a Network
  - @param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
  - @param networkId string - the network id
  - @param oldRegions []StandardNetworkRegionConfig - the old regions
  - @param newRegions []StandardNetworkRegionConfig - the new regions
  - @param d *schema.ResourceData - the terraform resource data
  - @param client *perimeter81Sdk.APIClient - the api client
  - @param oldStatusId string - the old status id (kept for API compatibility)

@return string, string, error
*/
func resourceRegionDelete(ctx context.Context, networkId string, oldRegions []StandardNetworkRegionConfig, newRegions []StandardNetworkRegionConfig, d *schema.ResourceData, client *perimeter81Sdk.APIClient, oldStatusId string) (string, string, error) {
	// Get the old regions that need to be deleted from the network
	for _, oldRegion := range oldRegions {
		// If the region does not exist in the new regions, delete it
		if !regionExistsInArray(oldRegion.CpRegionId, newRegions) {
			// Delete the region from the network
			result, _, err := client.StandardRegionsAPI.StandardNetworksControllerV2DeleteNetworkRegion(ctx, networkId).RemoveRegionDTO(perimeter81Sdk.RemoveRegionDTO{RegionId: oldRegion.RegionID}).Execute()
			if err != nil {
				d.Partial(true)
				return "", oldRegion.RegionID, err
			}
			// DeleteNetworkRegion returns its AsyncOperationResult inline — there
			// is no status URL to poll — so a non-2xx result.statusCode is the
			// only signal that the delete was rejected. Discarding it, as this
			// code used to, meant a rejected delete was reported as success.
			if !isSuccessStatus(int(result.GetStatusCode())) {
				d.Partial(true)
				return "", oldRegion.RegionID, &asyncFailedError{StatusCode: int(result.GetStatusCode()), Reasons: result.GetReason()}
			}

			// The delete responded 2xx, but the region can still be visible on
			// the network for a moment afterwards: it is eventually consistent.
			// resourceNetworkRead re-fetches the network right after this
			// function returns, so wait until the region is actually gone from
			// it — otherwise Read observes stale state.
			what := fmt.Sprintf("region %s to disappear from network %s", oldRegion.RegionID, networkId)
			pollErr := pollUntilConverged(ctx, func(ctx context.Context) (bool, *http.Response, error) {
				network, resp, err := client.StandardNetworksAPI.StandardNetworksControllerV2NetworkFind(ctx, networkId).Execute()
				if err != nil {
					return false, resp, err
				}
				for _, region := range network.Regions {
					if region.Id == oldRegion.RegionID {
						return false, resp, nil
					}
				}
				return true, resp, nil
			}, convergencePollInterval, convergenceTransientBudget, what)
			if pollErr != nil {
				d.Partial(true)
				return "", oldRegion.RegionID, pollErr
			}
		}
	}
	// AddNetworkRegion/DeleteNetworkRegion return their result inline with no
	// status URL: the convergence waits above already confirmed the change is
	// visible, so there is no async status id to carry forward.
	return oldStatusId, "", nil
}
