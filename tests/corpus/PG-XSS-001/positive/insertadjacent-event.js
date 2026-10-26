// corpus: expect=PG-XSS-001
window.addEventListener("message", (event) => {
  const feed = document.querySelector("#feed");
  feed.insertAdjacentHTML("beforeend", event.data.html);
});
