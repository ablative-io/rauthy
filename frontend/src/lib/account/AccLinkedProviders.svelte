<!-- Explicit provider linking keeps the original intent through reauthentication and recovery. -->
<script lang="ts">
    import type { UserResponse } from '$api/types/user';
    import { onMount } from 'svelte';
    import Button from '$lib5/button/Button.svelte';
    import { fetchDelete, fetchGet, fetchPost } from '$api/fetch';
    import type { AuthProvidersTemplate } from '$api/templates/AuthProvider';
    import type {
        ProviderLinkResponse,
        ProviderLinkIntentResponse,
        ProviderLinkAuditResponse,
    } from '$api/types/auth_provider';
    import { redirectToLogin, saveProviderToken } from '$utils/helpers';
    import { generatePKCE } from '$utils/pkce';
    import { PKCE_VERIFIER_UPSTREAM } from '$utils/constants';
    import { fetchSolvePow } from '$utils/pow';

    let {
        user = $bindable(),
        providers,
    }: { user: UserResponse; providers: AuthProvidersTemplate } = $props();
    const userId = $derived(user.id);
    const storageKey = 'identity-link-intent';
    const removalKey = 'identity-link-removal';
    let snapshot = $state<{
        links: ProviderLinkResponse[];
        operations: ProviderLinkAuditResponse[];
    }>();
    let pending = $state<{ id: string; provider: string; expires: number }>();
    let unlink = $state<{ operation_id: string; provider_id: string; subject: string }>();
    let busy = $state(false);
    let error = $state('');
    let message = $state('');
    const providerName = (id: string) => providers.find(p => p.id === id)?.name ?? id;

    function restoreIntent() {
        const value = sessionStorage.getItem(storageKey);
        if (!value) return;
        const parsed: unknown = JSON.parse(value);
        if (typeof parsed !== 'object' || parsed === null || !('user' in parsed)) {
            throw new Error('The saved link request cannot be read.');
        }
        if (parsed.user !== userId) {
            throw new Error(
                'This link request belongs to another account. Sign in to that account to continue.',
            );
        }
        if (
            !('id' in parsed) ||
            typeof parsed.id !== 'string' ||
            !('provider' in parsed) ||
            typeof parsed.provider !== 'string' ||
            !('expires' in parsed) ||
            typeof parsed.expires !== 'number'
        ) {
            throw new Error('The saved link request is incomplete.');
        }
        pending = { id: parsed.id, provider: parsed.provider, expires: parsed.expires };
    }

    function restoreRemoval() {
        const saved = sessionStorage.getItem(removalKey);
        if (!saved) return;
        const parsed: unknown = JSON.parse(saved);
        if (
            typeof parsed !== 'object' ||
            parsed === null ||
            !('user' in parsed) ||
            parsed.user !== userId ||
            !('operation_id' in parsed) ||
            typeof parsed.operation_id !== 'string' ||
            !('provider_id' in parsed) ||
            typeof parsed.provider_id !== 'string' ||
            !('subject' in parsed) ||
            typeof parsed.subject !== 'string'
        ) {
            throw new Error('The saved removal belongs to another account or cannot be read.');
        }
        unlink = {
            operation_id: parsed.operation_id,
            provider_id: parsed.provider_id,
            subject: parsed.subject,
        };
    }

    async function refresh() {
        const [links, operations] = await Promise.all([
            fetchGet<ProviderLinkResponse[]>('/auth/v1/providers/links'),
            fetchGet<ProviderLinkAuditResponse[]>('/auth/v1/providers/links/operations'),
        ]);
        if (!links.body || !operations.body) {
            throw new Error(
                links.error?.message ??
                    operations.error?.message ??
                    'Sign-in methods could not be read.',
            );
        }
        snapshot = { links: links.body, operations: operations.body };
        if (pending && snapshot.operations.some(op => op.source_operation_id === pending?.id)) {
            sessionStorage.removeItem(storageKey);
            pending = undefined;
        }
        if (
            unlink &&
            snapshot.operations.some(op => op.source_operation_id === unlink?.operation_id)
        ) {
            sessionStorage.removeItem(removalKey);
            unlink = undefined;
        }
    }

    async function act(work: () => Promise<void>) {
        if (busy) return;
        busy = true;
        error = '';
        try {
            await work();
        } catch (cause) {
            error =
                cause instanceof Error
                    ? cause.message
                    : 'The request could not be confirmed. Check its status before trying again.';
        } finally {
            busy = false;
        }
    }

    async function prepare(provider: string) {
        const res = await fetchPost<ProviderLinkIntentResponse>(
            `/auth/v1/providers/${provider}/link/prepare`,
        );
        if (!res.body)
            throw new Error(res.error?.message ?? 'The link request could not be prepared.');
        pending = { id: res.body.intent_id, provider, expires: res.body.expires_at };
        sessionStorage.setItem(storageKey, JSON.stringify({ ...pending, user: userId }));
        await redirectToLogin('account', true);
    }

    async function continueLink() {
        if (!pending) return;
        const pkce = await generatePKCE();
        if (!pkce) throw new Error('Your browser could not prepare a secure sign-in.');
        const pow = await fetchSolvePow();
        if (!pow) throw new Error('The sign-in security check could not be completed.');
        localStorage.setItem(PKCE_VERIFIER_UPSTREAM, pkce.verifier);
        const res = await fetchPost<string>(`/auth/v1/providers/${pending.provider}/link`, {
            intent_id: pending.id,
            pow,
            client_id: 'rauthy',
            redirect_uri: `${window.location.origin}/auth/v1/account`,
            provider_id: pending.provider,
            pkce_challenge: pkce.challenge,
        });
        const location = res.headers.get('location');
        if (!res.text || !location)
            throw new Error(
                res.error?.message ??
                    'The provider sign-in could not be confirmed. Your original request is retained.',
            );
        saveProviderToken(res.text);
        window.location.href = location;
    }

    async function removeLink(link: ProviderLinkResponse) {
        // Retain the original operation if a response is lost; never send a new removal.
        unlink = {
            operation_id: crypto.randomUUID(),
            provider_id: link.provider_id,
            subject: link.federation_uid,
        };
        sessionStorage.setItem(removalKey, JSON.stringify({ ...unlink, user: userId }));
    }

    async function confirmRemoval() {
        if (!unlink) return;
        const res = await fetchDelete<UserResponse>('/auth/v1/providers/link', unlink);
        if (!res.body)
            throw new Error(
                res.error?.message ??
                    'Removal could not be confirmed. Check status or retry this same request.',
            );
        user = res.body;
        message = 'Sign-in method removed. Check its audit status below.';
        await refresh();
    }

    onMount(() => {
        void act(async () => {
            restoreIntent();
            restoreRemoval();
            await refresh();
        });
    });
</script>

<section aria-labelledby="linked-sign-ins">
    <h3 id="linked-sign-ins">Sign-in methods</h3>
    <p>
        Connect another account to sign in as the same person. We will ask you to sign in again
        first.
    </p>
    {#if error}<p role="alert" class="error">{error}</p>{/if}
    {#if message}<p role="status">{message}</p>{/if}
    {#if snapshot}
        <ul>
            {#each snapshot.links as link (`${link.provider_id}:${link.federation_uid}`)}
                <li>
                    <span
                        >{providerName(link.provider_id)}{link.primary ? ' (primary)' : ''} · audit {link.audit}</span
                    >
                    <details>
                        <summary>Account identifier</summary><code>{link.federation_uid}</code>
                    </details>
                    <Button
                        level={3}
                        isDisabled={busy || !!unlink}
                        onclick={() => act(() => removeLink(link))}>Remove</Button
                    >
                </li>
            {:else}<li>No external accounts are connected.</li>{/each}
        </ul>
        {#each snapshot.operations.filter(op => op.state === 'pending') as operation (operation.source_operation_id)}
            <p role="status">
                {providerName(operation.provider_id)}: {operation.change}; identity audit awaiting
                acknowledgement.
            </p>
        {/each}
    {/if}
    {#if unlink}
        <p>Remove {providerName(unlink.provider_id)}? Another usable sign-in method must remain.</p>
        <Button isDisabled={busy} onclick={() => act(confirmRemoval)}>Confirm removal</Button>
    {/if}
    {#if pending}
        <p>Continue connecting {providerName(pending.provider)} after signing in again.</p>
        <p>This request expires at {new Date(pending.expires * 1000).toLocaleTimeString()}.</p>
        <Button isDisabled={busy} onclick={() => act(continueLink)}
            >Continue to {providerName(pending.provider)}</Button
        >
        <Button
            level={3}
            isDisabled={busy}
            onclick={() => act(() => redirectToLogin('account', true))}>Sign in again</Button
        >
    {:else if snapshot && !unlink}
        <div class="actions">
            {#each providers.filter(provider => !snapshot?.links.some(link => link.provider_id === provider.id)) as provider (provider.id)}
                <Button level={2} isDisabled={busy} onclick={() => act(() => prepare(provider.id))}
                    >Connect {provider.name}</Button
                >
            {/each}
        </div>
    {/if}
    <Button level={3} isDisabled={busy} onclick={() => act(refresh)}>Check status</Button>
</section>

<style>
    section {
        margin-block: 1rem;
        max-width: 36rem;
    }
    ul {
        padding-left: 1.25rem;
    }
    li {
        margin-block: 0.5rem;
    }
    .actions {
        display: flex;
        flex-wrap: wrap;
        gap: 0.5rem;
    }
    .error {
        color: hsl(var(--error));
    }
    code {
        overflow-wrap: anywhere;
    }
</style>
