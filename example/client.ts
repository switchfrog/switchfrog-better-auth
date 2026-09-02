import { createAuthClient } from "better-auth/client";
import { organizationClient } from "better-auth/client/plugins";

import { switchfrogClient } from "@switchfrog/better-auth/client";

const controls = document.querySelector<HTMLFieldSetElement>("#controls")!;
const status = document.querySelector<HTMLOutputElement>("#status")!;
const activeOrganization = document.querySelector<HTMLSelectElement>(
  "#active-organization",
)!;

function setStatus(message: string): void {
  status.value = message;
}

function resultMessage(result: unknown): string | null {
  if (typeof result !== "object" || result === null) return "The request failed.";
  const error = (result as { error?: unknown }).error;
  if (!error) return null;
  if (typeof error === "string") return error;
  if (typeof error === "object" && error !== null && "message" in error) {
    const message = (error as { message?: unknown }).message;
    if (typeof message === "string") return message;
  }
  return "The request failed.";
}

async function bootstrap(): Promise<void> {
  const response = await fetch("/config.json");
  if (!response.ok) throw new Error("Configuration is unavailable.");
  const configuration: unknown = await response.json();
  const publishableKey =
    typeof configuration === "object" &&
    configuration !== null &&
    typeof (configuration as { publishableKey?: unknown }).publishableKey === "string"
      ? (configuration as { publishableKey: string }).publishableKey.trim()
      : "";
  if (!publishableKey.startsWith("sf_pk_") || publishableKey.length === 6) {
    throw new Error("Configuration is invalid.");
  }

  const auth = createAuthClient({
    baseURL: `${location.origin}/api/auth`,
    plugins: [organizationClient(), switchfrogClient({ publishableKey })],
  });
  const organizationApi = auth.organization as unknown as {
    create(options: Readonly<{
      keepCurrentActiveOrganization: boolean;
      name: string;
      slug: string;
    }>): Promise<unknown>;
    setActive(options: Readonly<{ organizationId: string }>): Promise<unknown>;
  };
  const signUp = document.querySelector<HTMLFormElement>("#sign-up")!;
  const signIn = document.querySelector<HTMLFormElement>("#sign-in")!;
  const organization = document.querySelector<HTMLFormElement>("#organization")!;
  const active = document.querySelector<HTMLFormElement>("#active-organization-form")!;
  const signOut = document.querySelector<HTMLButtonElement>("#sign-out")!;

  signUp.addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = new FormData(signUp);
    const result = await auth.signUp.email({
      email: String(form.get("email") ?? ""),
      name: String(form.get("name") ?? ""),
      password: String(form.get("password") ?? ""),
    });
    setStatus(resultMessage(result) ?? "Account created.");
  });
  signIn.addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = new FormData(signIn);
    const result = await auth.signIn.email({
      email: String(form.get("email") ?? ""),
      password: String(form.get("password") ?? ""),
    });
    setStatus(resultMessage(result) ?? "Signed in.");
  });
  organization.addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = new FormData(organization);
    const result = await organizationApi.create({
      keepCurrentActiveOrganization: true,
      name: String(form.get("name") ?? ""),
      slug: String(form.get("slug") ?? ""),
    });
    const error = resultMessage(result);
    if (error) {
      setStatus(error);
      return;
    }
    const data = (result as { data?: { id?: unknown; name?: unknown } }).data;
    if (typeof data?.id === "string") {
      const option = new Option(
        typeof data.name === "string" ? data.name : data.id,
        data.id,
      );
      activeOrganization.add(option);
      activeOrganization.value = data.id;
    }
    setStatus("Organization created.");
  });
  active.addEventListener("submit", async (event) => {
    event.preventDefault();
    const result = await organizationApi.setActive({
      organizationId: activeOrganization.value,
    });
    setStatus(resultMessage(result) ?? "Active organization updated.");
  });
  signOut.addEventListener("click", async () => {
    const result = await auth.signOut();
    setStatus(resultMessage(result) ?? "Signed out.");
  });

  controls.disabled = false;
  setStatus("Ready.");
}

void bootstrap().catch((error) =>
  setStatus(error instanceof Error ? error.message : "Configuration is unavailable."),
);
