export type LatencyQuality = "idle" | "excellent" | "good" | "elevated";

export function classifyLatency(rttMs: number | null): {
  quality: LatencyQuality;
  label: string;
} {
  if (rttMs === null || Number.isNaN(rttMs)) {
    return { quality: "idle", label: "Medindo…" };
  }
  if (rttMs < 8) {
    return { quality: "excellent", label: "Excelente" };
  }
  if (rttMs < 25) {
    return { quality: "good", label: "Estável" };
  }
  return { quality: "elevated", label: "Latência elevada" };
}

export function formatRtt(rttMs: number | null): string {
  if (rttMs === null || Number.isNaN(rttMs)) {
    return "—";
  }
  if (rttMs < 1) {
    return "< 1 ms";
  }
  return `${rttMs.toFixed(1).replace(".", ",")} ms`;
}

export function formatTimestampPtBr(timestampMs: number | null): string {
  if (!timestampMs) {
    return "Nunca conectado";
  }
  return new Intl.DateTimeFormat("pt-BR", {
    dateStyle: "short",
    timeStyle: "short",
  }).format(new Date(timestampMs));
}

export function formatTimeOnlyPtBr(timestampMs: number): string {
  return new Intl.DateTimeFormat("pt-BR", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(new Date(timestampMs));
}

/**
 * Basic client-side validation for manual LAN IP input before IPC call.
 * Rejects empty values, whitespace, hostnames and invalid port ranges.
 */
export function validateManualTarget(
  rawIp: string,
  rawPort: string,
): { ok: true; ip: string; port?: number } | { ok: false; error: string } {
  const ip = rawIp.trim();
  if (!ip) {
    return { ok: false, error: "Informe o endereço IP da rede local." };
  }

  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const looksLikeIpv6 = ip.includes(":");

  if (ipv4Regex.test(ip)) {
    const octets = ip.split(".").map((part) => Number(part));
    if (octets.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
      return { ok: false, error: "Endereço IPv4 inválido." };
    }
    const [a = 0, b = 0] = octets;
    const isPrivateOrLocal =
      a === 10 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254) ||
      a === 127;
    if (!isPrivateOrLocal) {
      return {
        ok: false,
        error:
          "Apenas endereços da rede local (192.168.x.x, 10.x.x.x, 172.16-31.x.x ou loopback) são permitidos.",
      };
    }
  } else if (!looksLikeIpv6) {
    return {
      ok: false,
      error:
        "Use um endereço IP literal (ex.: 192.168.1.20). Nomes DNS não são aceitos.",
    };
  }

  const trimmedPort = rawPort.trim();
  if (!trimmedPort) {
    return { ok: true, ip };
  }
  if (!/^\d+$/.test(trimmedPort)) {
    return { ok: false, error: "A porta deve conter apenas números." };
  }
  const port = Number(trimmedPort);
  if (port < 1024 || port > 65535) {
    return {
      ok: false,
      error: "A porta deve estar entre 1024 e 65535.",
    };
  }

  return { ok: true, ip, port };
}
