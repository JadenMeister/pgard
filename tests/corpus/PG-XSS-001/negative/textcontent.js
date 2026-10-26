// corpus: expect=none
const params = new URLSearchParams(location.search);
const h1 = document.createElement("h1");
h1.textContent = "Hello " + params.get("name");
document.getElementById("greeting").append(h1);
