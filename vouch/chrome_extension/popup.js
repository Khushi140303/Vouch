const input = document.getElementById("apiBase");
const status = document.getElementById("status");

chrome.storage.local.get("apiBase", ({ apiBase }) => {
  input.value = apiBase || "http://localhost:8000";
});

document.getElementById("save").addEventListener("click", () => {
  const value = input.value.trim() || "http://localhost:8000";
  chrome.storage.local.set({ apiBase: value }, () => {
    status.textContent = "Saved. Reopen an email in Gmail to re-check.";
  });
});
