export type ApiCredentialOptions =
  | { type: "bearer"; token: string; }
  | { type: "token"; token: string; }
  | { type: "basic"; username: string; password: string; }
  | { type: "querystring"; name: string; value: string; }
  | { type: "custom"; authorization: string; };

export class ApiCredential {
  readonly #options: ApiCredentialOptions | undefined;

  constructor(
    optionsOrToken?: ApiCredentialOptions | string
  ) {
    this.#options = typeof optionsOrToken === "string"
      ? { type: "bearer", token: optionsOrToken }
      : optionsOrToken;
  }

  get headers(): Record<string, string> {
    if (!this.#options) {
      return {};
    }

    const options = this.#options;

    if (options.type === "bearer") {
      return { Authorization: `Bearer ${options.token}` };
    }
    if (options.type === "token") {
      return { Authorization: `token ${options.token}` };
    }
    if (options.type === "basic") {
      const encoded = Buffer.from(`${options.username}:${options.password}`).toString("base64");

      return { Authorization: `Basic ${encoded}` };
    }
    if (options.type === "querystring") {
      return {};
    }
    if (options.type === "custom") {
      return { Authorization: options.authorization };
    }

    return {};
  }

  get queryParams(): Record<string, string> {
    if (this.#options?.type === "querystring") {
      return {
        [this.#options.name]: this.#options.value
      };
    }

    return {};
  }
}
