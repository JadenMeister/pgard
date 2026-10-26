// corpus: expect=PG-XSS-001
const params = new URLSearchParams(location.search);
const name = params.get("name");
document.getElementById("greeting").innerHTML = `<h1>Hello ${name}</h1>`;
