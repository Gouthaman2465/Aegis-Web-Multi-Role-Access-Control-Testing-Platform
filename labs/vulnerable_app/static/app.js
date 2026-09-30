// Lab Dashboard Client Application
document.addEventListener("DOMContentLoaded", async () => {
    const dataEl = document.getElementById("app-data");
    const ownId = dataEl ? dataEl.getAttribute("data-user-id") : "1";
    const ownOrderId = dataEl ? dataEl.getAttribute("data-order-id") : "1";

    // Stage 2 planted test artifacts
    const AWS_DEV_KEY = "AKIAIOSFODNN7EXAMPLE";
    const LEGACY_EXPORT_PATH = "/api/legacy/export";

    try {
        // 1. Fetch API token with cookie credentials
        const tokenRes = await fetch("/api/token", { credentials: "same-origin" });
        if (!tokenRes.ok) {
            console.error("Token exchange failed");
            return;
        }
        const tokenData = await tokenRes.json();
        const token = tokenData.token;
        localStorage.setItem("lab_token", token);

        const authHeaders = {
            "Authorization": "Bearer " + token,
            "Accept": "application/json"
        };

        // 2. Fetch authenticated services (recorded by Playwright)
        await Promise.allSettled([
            fetch("/api/me", { headers: authHeaders }),
            fetch("/api/notifications", { headers: authHeaders }),
            fetch("/api/products", { headers: authHeaders }),
            fetch("/api/cors-reflect", { headers: authHeaders }),
            fetch("/api/internal/config"), // Unauthenticated endpoint
            fetch("/api/profile/" + ownId, { headers: authHeaders }),
            fetch("/api/orders/" + ownOrderId, { headers: authHeaders }),
            fetch("/api/admin/stats", { headers: authHeaders }),
        ]);

        const statusEl = document.getElementById("api-status");
        if (statusEl) {
            statusEl.textContent = "Application services loaded.";
        }
    } catch (err) {
        console.error("Error initializing lab client:", err);
    }
});
