import { InjectiveGrpcBase } from "../grpc/grpc-base.js";
import { PermissionsModuleParams, Namespace } from "@injectivelabs/sdk-ts";
import { Coin } from "@injectivelabs/core-proto-ts/cjs/cosmos/base/v1beta1/coin.js";

export async function getAddressesByRole(
    this: InjectiveGrpcBase,
    params: {
        denom: string;
        role: string;
    }
): Promise<
    {
        addresses: string;
    }[]
> {
    return this.request({
        method: this.chainGrpcPermissionsApi.fetchAddressesByRole,
        params,
    });
}

export async function getAddressRoles(
    this: InjectiveGrpcBase,
    params: {
        address: string;
        denom: string;
    }
): Promise<
    {
        roles: string;
    }[]
> {
    return this.request({
        method: this.chainGrpcPermissionsApi.fetchAddressRoles,
        params,
    });
}

export async function getAllNamespaces(
    this: InjectiveGrpcBase
): Promise<void[]> {
    return this.request({
        method: this.chainGrpcPermissionsApi.fetchAllNamespaces,
        params: {},
    });
}

export async function getPermissionsModuleParams(
    this: InjectiveGrpcBase
): Promise<PermissionsModuleParams> {
    return this.request({
        method: this.chainGrpcPermissionsApi.fetchModuleParams,
        params: {},
    });
}

export async function getNamespaceByDenom(
    this: InjectiveGrpcBase,
    params: {
        denom: string;
        includeRoles: boolean;
    }
): Promise<Namespace> {
    return this.request({
        method: this.chainGrpcPermissionsApi.fetchNamespaceByDenom,
        params,
    });
}

export async function getVouchersForAddress(
    this: InjectiveGrpcBase,
    params: {
        address: string;
    }
): Promise<
    {
        vouchers: Coin;
    }[]
> {
    return this.request({
        method: this.chainGrpcPermissionsApi.fetchVouchersForAddress,
        params,
    });
}
