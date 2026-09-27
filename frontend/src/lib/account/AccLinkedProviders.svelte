<script lang="ts">
    import Button from '$lib5/button/Button.svelte';
    import ButtonAuthProvider from '$lib/ButtonAuthProvider.svelte';
    import { useI18n } from '$state/i18n.svelte.js';
    import type { UserResponse } from '$api/types/user.ts';
    import type { AuthProvidersTemplate } from '$api/templates/AuthProvider.ts';
    import type { ProviderLinkResponse, ProviderLoginRequest } from '$api/types/auth_provider.ts';
    import { fetchDelete, fetchGet, fetchPost } from '$api/fetch';
    import { PKCE_VERIFIER_UPSTREAM } from '$utils/constants';
    import { saveProviderToken } from '$utils/helpers';
    import { generatePKCE } from '$utils/pkce';
    import { fetchSolvePow } from '$utils/pow';
    import { onMount } from 'svelte';

    let {
        user = $bindable(),
        providers,
    }: {
        user: UserResponse;
        providers: AuthProvidersTemplate;
    } = $props();

    let t = useI18n();

    let links: ProviderLinkResponse[] = $state([]);
    let err = $state('');
    let isLoading = $state(false);

    let unlinked = $derived(providers.filter(p => !links.some(l => l.provider_id === p.id)));

    onMount(() => {
        fetchLinks();
    });

    async function fetchLinks() {
        let res = await fetchGet<ProviderLinkResponse[]>('/auth/v1/providers/links');
        if (res.body) {
            links = res.body;
        } else {
            err = res.error?.message || 'Error fetching the provider links';
        }
    }

    function linkProvider(id: string) {
        err = '';
        generatePKCE().then(pkce => {
            if (pkce) {
                localStorage.setItem(PKCE_VERIFIER_UPSTREAM, pkce.verifier);
                startLink(id, pkce.challenge);
            }
        });
    }

    async function startLink(id: string, pkce_challenge: string) {
        isLoading = true;

        let pow = (await fetchSolvePow()) || '';
        let payload: ProviderLoginRequest = {
            email: user.email,
            pow,
            client_id: 'rauthy',
            redirect_uri: window.location.href,
            provider_id: id,
            pkce_challenge,
        };

        let res = await fetchPost<string>(`/auth/v1/providers/${id}/link`, payload);
        isLoading = false;

        if (res.text && res.status === 202) {
            saveProviderToken(res.text);
            let loc = res.headers.get('location');
            if (loc) {
                window.location.href = loc;
            }
        } else {
            // 428: the person must sign in again before linking another provider
            err = res.error?.message || `HTTP ${res.status}`;
        }
    }

    async function unlinkProvider(id: string) {
        err = '';
        let res = await fetchDelete<UserResponse>(`/auth/v1/providers/${id}/link`);
        if (res.body) {
            user = res.body;
            await fetchLinks();
        } else {
            err = res.error?.message || t.account.providerUnlinkDesc;
        }
    }
</script>

<div class="container">
    {#each links as link (link.provider_id)}
        <div class="link">
            <div>
                <div class="name">{link.provider_name}</div>
                <div class="meta">
                    {link.federation_uid}
                    {#if link.primary}
                        &middot; primary
                    {/if}
                    &middot; audit {link.audit}
                </div>
            </div>
            <Button
                ariaLabel={`${t.account.providerUnlink}: ${link.provider_name}`}
                level={3}
                onclick={() => unlinkProvider(link.provider_id)}
            >
                {t.account.providerUnlink}
            </Button>
        </div>
    {/each}

    {#if unlinked.length > 0}
        <p>{t.account.providerLinkDesc}</p>
        <div class="providers">
            {#each unlinked as provider (provider.id)}
                <ButtonAuthProvider
                    ariaLabel={`${t.account.providerLink}: ${provider.name}`}
                    {provider}
                    onclick={linkProvider}
                    {isLoading}
                />
            {/each}
        </div>
    {/if}

    {#if err}
        <div class="err">{err}</div>
    {/if}
</div>

<style>
    .container {
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
        margin-bottom: 1rem;
    }

    .err {
        color: hsl(var(--error));
    }

    .link {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 1rem;
    }

    .meta {
        color: hsla(var(--text) / 0.66);
        font-size: 0.9rem;
        word-break: break-all;
    }

    .providers {
        display: flex;
        flex-wrap: wrap;
        gap: 0.5rem;
    }
</style>
