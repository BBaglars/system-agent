// Skills live at the project root so they stay free of framework-specific imports.
// The LangChain tool() wrapper is applied in agent.ts where node_modules are resolved.

interface IpApiResponse {
  country?: string;
  isp?: string;
  org?: string;
  status?: string;
  message?: string;
}

// Calls ip-api.com and returns a human-readable summary of country, ISP, and org.
async function lookupIpInfo(ip: string): Promise<string> {
  try {
    const response = await fetch(`http://ip-api.com/json/${ip}`);

    if (!response.ok) {
      return `IP lookup failed: HTTP ${response.status}`;
    }

    const data = (await response.json()) as IpApiResponse;

    if (data.status === "fail") {
      return `IP lookup failed: ${data.message ?? "unknown reason"}`;
    }

    return `Country: ${data.country ?? "unknown"}, ISP: ${data.isp ?? "unknown"}, Org: ${data.org ?? "unknown"}`;
  } catch (error) {
    // Surface errors without crashing the caller.
    return `IP lookup error: ${String(error)}`;
  }
}

module.exports = { lookupIpInfo };
