import { Cookie, SetCookie, type SetCookieInit } from "@mjackson/headers";
import {
	Discord,
	OAuth2RequestError,
	type OAuth2Tokens,
	UnexpectedErrorResponseBodyError,
	UnexpectedResponseError,
	generateState,
} from "arctic";
import createDebug from "debug";
import { Strategy } from "remix-auth/strategy";
import { redirect } from "./lib/redirect.js";

type URLConstructor = ConstructorParameters<typeof URL>[0];

const debug = createDebug("DiscordStrategy");

export {
	OAuth2RequestError,
	UnexpectedResponseError,
	UnexpectedErrorResponseBodyError,
};

export const NAME = "discord";

export class DiscordStrategy<User> extends Strategy<
	User,
	DiscordStrategy.VerifyOptions
> {
	name = NAME;

	protected client: Discord;

	constructor(
		protected options: DiscordStrategy.ConstructorOptions,
		verify: Strategy.VerifyFunction<User, DiscordStrategy.VerifyOptions>,
	) {
		super(verify);

		this.client = new Discord(
			options.clientId,
			options.clientSecret,
			options.redirectURI.toString(),
		);

		if (
			this.options.scopes?.includes("applications.commands") &&
			!this.options.integrationType
		) {
			throw new Error(
				"integrationType is required when scope contains applications.commands",
			);
		}
		if (
			this.options.integrationType &&
			!Object.values(DiscordStrategy.IntegrationType).includes(
				this.options.integrationType,
			)
		) {
			throw new Error("integrationType must be a valid DiscordIntegrationType");
		}
	}

	private get cookieName() {
		if (typeof this.options.cookie === "string") {
			return this.options.cookie || NAME;
		}
		return this.options.cookie?.name ?? NAME;
	}

	private get cookieOptions() {
		if (typeof this.options.cookie !== "object") return {};
		return this.options.cookie ?? {};
	}

	override async authenticate(request: Request): Promise<User> {
		debug("Request URL", request.url);

		const url = new URL(request.url);

		const stateUrl = url.searchParams.get("state");
		const error = url.searchParams.get("error");

		if (error) {
			const description = url.searchParams.get("error_description");
			const uri = url.searchParams.get("error_uri");
			throw new OAuth2RequestError(error, description, uri, stateUrl);
		}

		if (!stateUrl) {
			debug("No state found in the URL, redirecting to authorization endpoint");

			const state = generateState();

			debug("Generated State", state);

			const url = this.client.createAuthorizationURL(
				state,
				null,
				this.options.scopes ?? [],
			);

			url.search = this.authorizationParams(
				url.searchParams,
				request,
			).toString();

			debug("Authorization URL", url.toString());

			const header = new SetCookie({
				name: this.cookieName,
				value: new URLSearchParams({ state }).toString(),
				httpOnly: true, // Prevents JavaScript from accessing the cookie
				maxAge: 60 * 5, // 5 minutes
				path: "/", // Allow the cookie to be sent to any path
				sameSite: "Lax", // Prevents it from being sent in cross-site requests
				...this.cookieOptions,
			});

			throw redirect(url.toString(), {
				headers: { "Set-Cookie": header.toString() },
			});
		}

		const code = url.searchParams.get("code");

		if (!code) throw new ReferenceError("Missing code in the URL");

		const cookie = new Cookie(request.headers.get("cookie") ?? "");
		const params = new URLSearchParams(cookie.get(this.cookieName));

		if (!params.has("state")) {
			throw new ReferenceError("Missing state on cookie.");
		}

		if (params.get("state") !== stateUrl) {
			throw new RangeError("State in URL doesn't match state in cookie.");
		}

		debug("Validating authorization code");
		const tokens = await this.client.validateAuthorizationCode(code, null);

		debug("Verifying the user profile");
		const user = await this.verify({ request, tokens });

		debug("User authenticated");
		return user;
	}

	/**
	 * Return extra parameters to be included in the authorization request.
	 *
	 * Some OAuth 2.0 providers allow additional, non-standard parameters to be
	 * included when requesting authorization.  Since these parameters are not
	 * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
	 * strategies can override this function in order to populate these
	 * parameters as required by the provider.
	 */
	protected authorizationParams(
		params: URLSearchParams,
		_: Request,
	): URLSearchParams {
		if (this.options.integrationType) {
			params.set("integration_type", this.options.integrationType.toString());
		}
		if (this.options.prompt) {
			params.set("prompt", this.options.prompt);
		}
		return params;
	}

	/**
	 * Get a new OAuth2 Tokens object using the refresh token once the previous
	 * access token has expired.
	 * @param refreshToken The refresh token to use to get a new access token
	 * @returns The new OAuth2 tokens object
	 * @example
	 * ```ts
	 * let tokens = await strategy.refreshToken(refreshToken);
	 * console.log(tokens.accessToken());
	 * ```
	 */
	public refreshToken(refreshToken: string) {
		return this.client.refreshAccessToken(refreshToken);
	}
}

export namespace DiscordStrategy {
	export interface VerifyOptions {
		/** The request that triggered the verification flow */
		request: Request;
		/** The OAuth2 tokens retrivied from the identity provider */
		tokens: OAuth2Tokens;
	}

	export interface ConstructorOptions {
		/**
		 * The name of the cookie used to keep state and code verifier around.
		 *
		 * The OAuth2 flow requires generating a random state and code verifier, and
		 * then checking that the state matches when the user is redirected back to
		 * the application. This is done to prevent CSRF attacks.
		 *
		 * The state and code verifier are stored in a cookie, and this option
		 * allows you to customize the name of that cookie if needed.
		 * @default "discord"
		 */
		cookie?: string | (Omit<SetCookieInit, "value"> & { name: string });

		/**
		 * This is the Client ID of your application, provided to you by the Identity
		 * Provider you're using to authenticate users.
		 */
		clientId: string;
		/**
		 * This is the Client Secret of your application, provided to you by the
		 * Identity Provider you're using to authenticate users.
		 */
		clientSecret: string;

		/**
		 * The URL of your application where the Identity Provider will redirect the
		 * user after they've logged in or authorized your application.
		 */
		redirectURI: URLConstructor;

		/**
		 * The scopes you want to request from the Identity Provider, this is a list
		 * of strings that represent the permissions you want to request from the
		 * user.
		 */
		scopes?: Scope[];

		/**
		 * The integration_type parameter specifies the installation context for the
		 * authorization. The installation context determines where the application
		 * will be installed, and is only relevant when scope contains applications.commands.
		 */
		integrationType?: IntegrationType;

		/**
		 * prompt controls how the authorization flow handles existing authorizations.
		 */
		prompt?: Prompt;
	}

	/**
	 * These are all the available scopes Discord allows.
	 * @see https://discord.com/developers/docs/topics/oauth2#shared-resources-oauth2-scopes
	 */
	export type Scope =
		| "activities.read"
		| "activities.write"
		| "applications.builds.read"
		| "applications.builds.upload"
		| "applications.commands"
		| "applications.commands.update"
		| "applications.commands.permissions.update"
		| "applications.entitlements"
		| "applications.store.update"
		| "bot"
		| "connections"
		| "dm_channels.read"
		| "email"
		| "gdm.join"
		| "guilds"
		| "guilds.join"
		| "guilds.members.read"
		| "identify"
		| "messages.read"
		| "relationships.read"
		| "role_connections.write"
		| "rpc"
		| "rpc.activities.write"
		| "rpc.notifications.read"
		| "rpc.voice.read"
		| "rpc.voice.write"
		| "voice"
		| "webhook.incoming";

	/**
	 * The integration_type parameter specifies the installation context for the authorization.
	 * The installation context determines where the application will be installed,
	 * and is only relevant when scope contains applications.commands.
	 * When set to 0 (GUILD_INSTALL) the application will be authorized for installation to a server,
	 * and when set to 1 (USER_INSTALL) the application will be authorized for installation to a user.
	 * The application must be configured in the Developer Portal to support the provided integration_type.
	 * @see https://discord.com/developers/docs/resources/application#application-object-application-integration-types
	 *
	 */
	export enum IntegrationType {
		GUILD_INSTALL = 0,
		USER_INSTALL = 1,
	}

	/**
	 * If a user has previously authorized your application with the requested scopes
	 * and prompt is set to consent, it will request them to reapprove their authorization.
	 * If set to none, it will skip the authorization screen and redirect them back to your
	 * redirect URI without requesting their authorization.
	 */
	export enum Prompt {
		NONE = "none",
		CONSENT = "consent",
	}
}
