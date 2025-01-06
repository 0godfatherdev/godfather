import { InjectiveGrpcBase } from "../grpc/grpc-base.js";
import {
    AuthorityMetadata,
    TokenFactoryModuleParams,
    TokenFactoryModuleState,
} from "@injectivelabs/sdk-ts";

export async function getDenomsFromCreator(
    this: InjectiveGrpcBase,
    params: string
): Promise<string[]> {
    return this.request({
        method: this.chainGrpcTokenFactoryApi.fetchDenomsFromCreator,
        params,
    });
}

export async function getDenomAuthorityMetadata(
    this: InjectiveGrpcBase,
    params: {
        creator: string;
        subDenom: string;
    }
): Promise<AuthorityMetadata> {
    return this.request({
        method: (params: { creator: string; subDenom: string }) =>
            this.chainGrpcTokenFactoryApi.fetchDenomAuthorityMetadata(
                params.creator,
                params.subDenom
            ),
        params,
    });
}

export async function getTokenFactoryModuleParams(
    this: InjectiveGrpcBase
): Promise<TokenFactoryModuleParams> {
    return this.request({
        method: this.chainGrpcTokenFactoryApi.fetchModuleParams,
        params: {},
    });
}

export async function getTokenFactoryModuleState(
    this: InjectiveGrpcBase
): Promise<TokenFactoryModuleState> {
    return this.request({
        method: this.chainGrpcTokenFactoryApi.fetchModuleState,
        params: {},
    });
}
