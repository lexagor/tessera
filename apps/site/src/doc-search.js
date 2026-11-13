const search = document.getElementById("doc-search");
search?.addEventListener("input", () => {
  const q = search.value.trim().toLowerCase();
  document.querySelectorAll(".sidebar li").forEach((item) => {
    item.style.display = !q || item.textContent.toLowerCase().includes(q) ? "" : "none";
  });
});
