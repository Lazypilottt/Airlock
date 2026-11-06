// Live timeline: prepend decisions as they arrive (server-sent events).
// Kept to plain DOM APIs so the dashboard has no third-party assets.
"use strict";

document.addEventListener("DOMContentLoaded", () => {
  const table = document.getElementById("timeline");
  if (!table || !window.EventSource) {
    return;
  }
  const body = table.tBodies[0];
  const base = table.dataset.live;
  const after = table.dataset.after || "0";
  const source = new EventSource(`${base}${base.includes("?") ? "&" : "?"}after=${after}`);
  source.addEventListener("decision", (event) => {
    // The row is rendered and escaped by the server; parse it as a table row.
    const template = document.createElement("template");
    template.innerHTML = `<table><tbody>${event.data}</tbody></table>`;
    const row = template.content.querySelector("tr");
    if (!row || body.querySelector(`tr[data-id="${row.dataset.id}"]`)) {
      return;
    }
    const empty = body.querySelector("tr.empty");
    if (empty) {
      empty.remove();
    }
    row.classList.add("new");
    body.insertBefore(row, body.firstChild);
  });
});
