import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import * as api from "../api";
import type { Entitlements, Member, Org } from "../api";
import { TeamPanel } from "../TeamPanel";

vi.mock("../api", () => ({
  createCheckout: vi.fn(),
  createPortal: vi.fn(),
  fetchAudit: vi.fn(),
  fetchEntitlements: vi.fn(),
  fetchMembers: vi.fn(),
  fetchOrgs: vi.fn(),
  grantOrgKey: vi.fn(),
  inviteMember: vi.fn(),
}));

vi.mock("../vault", () => ({
  decryptOrgName: vi.fn(),
  openOrgKey: vi.fn(),
  sealGrantTo: vi.fn(),
}));

afterEach(cleanup);

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

function org(id: string): Org {
  return { id, encName: new Uint8Array(), role: "member", encOrgKey: null };
}

function member(userId: string): Member {
  return { userId, role: "member", publicKey: null };
}

const freePlan: Entitlements = {
  tier: "free",
  effectiveTier: "free",
  trialEndsAt: null,
  limits: { maxMembers: 3, maxOrgProjects: 1 },
  billingEnabled: false,
};

describe("TeamPanel organisation loading", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(api.fetchOrgs).mockResolvedValue([org("org-a"), org("org-b")]);
    vi.mocked(api.fetchEntitlements).mockResolvedValue(freePlan);
  });

  it("keeps details from the latest organisation when requests resolve out of order", async () => {
    const first = deferred<Member[]>();
    const second = deferred<Member[]>();
    vi.mocked(api.fetchMembers).mockImplementation((orgId) =>
      orgId === "org-a" ? first.promise : second.promise,
    );

    render(
      <TeamPanel master={new Uint8Array(32)} encPrivateKeys={new Uint8Array([1])} />,
    );

    fireEvent.click(await screen.findByRole("button", { name: /org-a/ }));
    fireEvent.click(screen.getByRole("button", { name: /org-b/ }));

    await act(async () => {
      second.resolve([member("member-b")]);
    });
    expect(await screen.findByText("member-b")).toBeInTheDocument();

    await act(async () => {
      first.resolve([member("member-a")]);
    });
    expect(screen.getByRole("heading", { name: "Members of org-b" })).toBeInTheDocument();
    expect(screen.getByText("member-b")).toBeInTheDocument();
    expect(screen.queryByText("member-a")).not.toBeInTheDocument();
    expect(api.fetchEntitlements).toHaveBeenCalledOnce();
    expect(api.fetchEntitlements).toHaveBeenCalledWith("org-b");
  });
});
