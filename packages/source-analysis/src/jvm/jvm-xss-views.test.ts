import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, afterEach, describe, expect, it } from "vitest";
import { scanSourceCode } from "../scan-source.js";
import { TreeSitterRuntime } from "../tree-sitter/runtime.js";
import { analyzeJvmTree } from "./analyze-jvm.js";
import { analyzeThymeleaf, type ModelSource } from "./templates.js";

/**
 * Model attributes and the views they are linked to (#338): `setViewName`, constants, flash
 * attributes on a redirect, `@ModelAttribute` methods. A link is only made when it is proven;
 * anything else keeps the name-only match, so no finding is lost.
 */

const runtime = new TreeSitterRuntime();
afterAll(() => runtime.dispose());

async function run(source: string, file = "C.java") {
  const language = file.endsWith(".kt") ? "kotlin" : "java";
  const outcome = await runtime.parse(language, source);
  if (outcome.status !== "parsed") throw new Error(`not parsed: ${outcome.status}`);
  try {
    return analyzeJvmTree(outcome.tree.rootNode, source, file, language);
  } finally {
    outcome.dispose();
  }
}

const HEAD =
  "import org.springframework.stereotype.Controller;\nimport org.springframework.ui.Model;\nimport org.springframework.web.bind.annotation.*;\nimport org.springframework.web.servlet.ModelAndView;\nimport org.springframework.web.servlet.mvc.support.RedirectAttributes;\n";
const controller = (members: string, annotations = "@Controller"): string =>
  `${HEAD}${annotations}\nclass C {\n${members}\n}\n`;

const attributeOf = async (source: string, name: string) =>
  (await run(source)).modelAttributes.find((attribute) => attribute.name === name);

describe("mav.setViewName (#338)", () => {
  it("links the attribute to the view", async () => {
    const source = controller(
      '@GetMapping("/a") ModelAndView a(@RequestParam String q) {\nModelAndView mav = new ModelAndView();\nmav.setViewName("search");\nmav.addObject("title", q);\nreturn mav;\n}',
    );
    expect(await attributeOf(source, "title")).toMatchObject({ views: ["search"], tainted: true });
  });
  it("a view name that is a variable is not resolved: the match stays by name", async () => {
    const source = controller(
      '@GetMapping("/a") ModelAndView a(@RequestParam String q, @RequestParam String v) {\nModelAndView mav = new ModelAndView();\nmav.setViewName(v);\nmav.addObject("title", q);\nreturn mav;\n}',
    );
    const found = await attributeOf(source, "title");
    expect(found?.views).toEqual([]);
    expect(found?.partial).toBe(true);
  });
  it("setViewName on something that is not a model object is ignored", async () => {
    const source = controller(
      '@GetMapping("/a") String a(@RequestParam String q, Model model, Other other) {\nother.setViewName("elsewhere");\nmodel.addAttribute("title", q);\nreturn "search";\n}',
    );
    expect((await attributeOf(source, "title"))?.views).toEqual(["search"]);
  });
  it("Kotlin: mav.viewName = is read too", async () => {
    const source = `import org.springframework.stereotype.Controller\nimport org.springframework.web.bind.annotation.*\nimport org.springframework.web.servlet.ModelAndView\n@Controller\nclass C {\n  @GetMapping("/a") fun a(@RequestParam q: String): ModelAndView {\n    val mav = ModelAndView()\n    mav.viewName = "search"\n    mav.addObject("title", q)\n    return mav\n  }\n}\n`;
    const attributes = (await run(source, "C.kt")).modelAttributes;
    expect(attributes.find((a) => a.name === "title")?.views).toEqual(["search"]);
  });
});

describe("a view returned through a constant (#338)", () => {
  const constants =
    'static final String PROFILE = "profile";\nprivate static final String DIR = "pages/";\nstatic String mutable = "loose";\n';
  it("a static final String of the file", async () => {
    const source = controller(
      `${constants}@GetMapping("/b") String b(@RequestParam String bio, Model model) {\nmodel.addAttribute("bio", bio);\nreturn PROFILE;\n}`,
    );
    expect(await attributeOf(source, "bio")).toMatchObject({ views: ["profile"] });
    expect((await attributeOf(source, "bio"))?.partial).toBeUndefined();
  });
  it("a concatenation of constants and literals", async () => {
    const source = controller(
      `${constants}@GetMapping("/b") String b(@RequestParam String bio, Model model) {\nmodel.addAttribute("bio", bio);\nreturn DIR + "note";\n}`,
    );
    expect((await attributeOf(source, "bio"))?.views).toEqual(["pages/note"]);
  });
  it("a constant of another class in the file", async () => {
    const source = `${controller(
      '@GetMapping("/b") String b(@RequestParam String bio, Model model) {\nmodel.addAttribute("bio", bio);\nreturn Views.PROFILE;\n}',
    )}class Views { static final String PROFILE = "profile"; }\n`;
    expect((await attributeOf(source, "bio"))?.views).toEqual(["profile"]);
  });
  it("a constant defined in another file is not resolved: name-only, partial", async () => {
    const source = controller(
      '@GetMapping("/b") String b(@RequestParam String bio, Model model) {\nmodel.addAttribute("bio", bio);\nreturn Elsewhere.PROFILE;\n}',
    );
    const found = await attributeOf(source, "bio");
    expect(found?.views).toEqual([]);
    expect(found?.partial).toBe(true);
  });
  it("a non-final field is not a fixed view", async () => {
    const source = controller(
      `${constants}@GetMapping("/b") String b(@RequestParam String bio, Model model) {\nmodel.addAttribute("bio", bio);\nreturn mutable;\n}`,
    );
    expect((await attributeOf(source, "bio"))?.views).toEqual([]);
  });
  it("a local that holds two values is not a fixed view", async () => {
    const source = controller(
      '@GetMapping("/b") String b(@RequestParam String bio, Model model) {\nString v = "one";\nif (bio.isEmpty()) { v = "two"; }\nmodel.addAttribute("bio", bio);\nreturn v;\n}',
    );
    expect((await attributeOf(source, "bio"))?.views).toEqual([]);
  });
  it("both branches of a condition count, and a branch that is not fixed makes it partial", async () => {
    const both = controller(
      '@GetMapping("/b") String b(@RequestParam String bio, Model model) {\nmodel.addAttribute("bio", bio);\nreturn bio.isEmpty() ? "empty" : "full";\n}',
    );
    expect((await attributeOf(both, "bio"))?.views).toEqual(["empty", "full"]);
    const mixed = controller(
      '@GetMapping("/b") String b(@RequestParam String bio, Model model) {\nmodel.addAttribute("bio", bio);\nreturn bio.isEmpty() ? "empty" : bio;\n}',
    );
    expect(await attributeOf(mixed, "bio")).toMatchObject({ views: ["empty"], partial: true });
  });
  it("a literal in one branch and an unresolved view in another keeps the first and is partial", async () => {
    const source = controller(
      '@GetMapping("/b") String b(@RequestParam String bio, Model model) {\nmodel.addAttribute("bio", bio);\nif (bio.isEmpty()) { return "empty"; }\nreturn pick(bio);\n}',
    );
    expect(await attributeOf(source, "bio")).toMatchObject({ views: ["empty"], partial: true });
  });
  it("Kotlin const val", async () => {
    const source = `import org.springframework.stereotype.Controller\nimport org.springframework.ui.Model\nimport org.springframework.web.bind.annotation.*\nconst val PROFILE = "profile"\n@Controller\nclass C {\n  @GetMapping("/b") fun b(@RequestParam bio: String, model: Model): String {\n    model.addAttribute("bio", bio)\n    return PROFILE\n  }\n}\n`;
    expect((await run(source, "C.kt")).modelAttributes[0]?.views).toEqual(["profile"]);
  });
});

describe("flash attributes on a redirect (#338)", () => {
  const save = (target: string, extra = ""): string =>
    controller(
      `@PostMapping("/save") String save(@RequestParam String msg, RedirectAttributes ra) {\nra.addFlashAttribute("msg", msg);\nreturn "redirect:${target}";\n}\n${extra}`,
      '@Controller\n@RequestMapping("/app")',
    );
  const thanks =
    '@GetMapping("/thanks") String thanks() { return "thanks"; }\n@GetMapping("/other") String other() { return "other"; }';
  it("links to the view of the handler the redirect leads to", async () => {
    const found = await attributeOf(save("/app/thanks", thanks), "msg");
    expect(found?.views).toEqual(["thanks"]);
    expect(found?.partial).toBeUndefined();
  });
  it("a query string on the redirect does not matter", async () => {
    expect((await attributeOf(save("/app/thanks?ok=1", thanks), "msg"))?.views).toEqual(["thanks"]);
  });
  it("a path variable in the mapping matches a literal target", async () => {
    const extra =
      '@GetMapping("/items/{id}") String item(@PathVariable String id) { return "item"; }';
    expect((await attributeOf(save("/app/items/7", extra), "msg"))?.views).toEqual(["item"]);
  });
  it("a redirect to a handler this file does not have stays by name", async () => {
    const found = await attributeOf(save("/app/missing", thanks), "msg");
    expect(found?.views).toEqual([]);
    expect(found?.partial).toBe(true);
  });
  it("only handlers that answer a GET are a redirect target", async () => {
    const extra = '@PostMapping("/post-only") String p() { return "post-view"; }';
    const found = await attributeOf(save("/app/post-only", extra), "msg");
    expect(found?.views).toEqual([]);
    expect(found?.partial).toBe(true);
  });
  it("a target that is not a literal is not followed", async () => {
    const source = controller(
      '@PostMapping("/save") String save(@RequestParam String msg, @RequestParam String id, RedirectAttributes ra) {\nra.addFlashAttribute("msg", msg);\nreturn "redirect:/app/items/" + id;\n}\n@GetMapping("/items/{id}") String item() { return "item"; }',
      '@Controller\n@RequestMapping("/app")',
    );
    expect(await attributeOf(source, "msg")).toMatchObject({ views: [], partial: true });
  });
  it("a plain Model attribute on a redirect is not linked to the target (the query string carries it)", async () => {
    const source = controller(
      '@PostMapping("/save") String save(@RequestParam String msg, Model model) {\nmodel.addAttribute("msg", msg);\nreturn "redirect:/thanks";\n}\n@GetMapping("/thanks") String thanks() { return "thanks"; }',
    );
    expect((await attributeOf(source, "msg"))?.views).toEqual([]);
  });
});

describe("redirect target resolution (#338 review)", () => {
  const save = (target: string, extra: string): string =>
    controller(
      `@PostMapping("/save") String save(@RequestParam String msg, RedirectAttributes ra) {\nra.addFlashAttribute("msg", msg);\nreturn "redirect:${target}";\n}\n${extra}`,
      '@Controller\n@RequestMapping("/shop")',
    );
  const both =
    '@GetMapping("/item/list") String list() { return "list"; }\n@GetMapping("/item/{id}") String detail(@PathVariable String id) { return "detail"; }';
  it("a literal mapping wins over a templated one", async () => {
    const found = await attributeOf(save("/shop/item/list", both), "msg");
    expect(found?.views).toEqual(["list"]);
  });
  it("a templated mapping is used when no literal one matches", async () => {
    const found = await attributeOf(save("/shop/item/7", both), "msg");
    expect(found?.views).toEqual(["detail"]);
  });
  it("a relative redirect is not resolved", async () => {
    const found = await attributeOf(
      save("list", '@GetMapping("/list") String other() { return "unrelated"; }'),
      "msg",
    );
    expect(found?.views).toEqual([]);
    expect(found?.partial).toBe(true);
  });
  it("a literal mapping that is not a GET stops the templated one from being used", async () => {
    const extra =
      '@PostMapping("/item/list") String p() { return "post-view"; }\n@GetMapping("/item/{id}") String detail(@PathVariable String id) { return "detail"; }';
    const found = await attributeOf(save("/shop/item/list", extra), "msg");
    expect(found?.views).toEqual([]);
    expect(found?.partial).toBe(true);
  });
  it("attributes of one name that lead to the same views are one source", async () => {
    const source = controller(
      '@PostMapping("/a") String a(@RequestParam String m, RedirectAttributes ra) { ra.addFlashAttribute("m", m); return "redirect:/t"; }\n@PostMapping("/b") String b(@RequestParam String m, RedirectAttributes ra) { ra.addFlashAttribute("m", m); return "redirect:/t"; }\n@GetMapping("/t") String t() { return "t"; }',
    );
    expect((await run(source)).modelAttributes.filter((a) => a.name === "m")).toHaveLength(1);
  });
});

describe("@ModelAttribute methods (#338)", () => {
  const handlers =
    '@GetMapping("/a") String a() { return "first"; }\n@GetMapping("/b") String b() { return "second"; }';
  it("a returned value applies to every view of the controller", async () => {
    const source = controller(
      `@ModelAttribute("banner") String banner(@RequestParam String b) { return b; }\n${handlers}`,
    );
    expect(await attributeOf(source, "banner")).toMatchObject({
      views: ["first", "second"],
      tainted: true,
      partial: true,
    });
  });
  it("the name comes from the return type when the annotation gives none", async () => {
    const source = controller(
      `@ModelAttribute String theme(@RequestParam String t) { return t; }\n@ModelAttribute List<Item> items(@RequestParam String t) { return load(t); }\n${handlers}`,
    );
    const names = (await run(source)).modelAttributes.map((attribute) => attribute.name);
    expect(names).toContain("string");
    expect(names).toContain("itemList");
  });
  it("a void method that fills the model applies to every view", async () => {
    const source = controller(
      `@ModelAttribute void common(Model model, @RequestParam String theme) { model.addAttribute("theme", theme); }\n${handlers}`,
    );
    expect(await attributeOf(source, "theme")).toMatchObject({
      views: ["first", "second"],
      partial: true,
    });
  });
  it("a value that is not request input is not tainted", async () => {
    const source = controller(
      `@ModelAttribute("site") String site() { return "pgard"; }\n${handlers}`,
    );
    expect((await attributeOf(source, "site"))?.tainted).toBe(false);
  });
  it("in a controller with no resolvable view the attribute keeps the name-only match", async () => {
    const source = controller(
      '@ModelAttribute("banner") String banner(@RequestParam String b) { return b; }\n@GetMapping("/a") String a(@RequestParam String v) { return v; }',
    );
    expect(await attributeOf(source, "banner")).toMatchObject({ views: [], partial: true });
  });
  it("is not a view-returning handler: its return value is not read as a view name", async () => {
    const source = controller(
      `@ModelAttribute("banner") String banner(@RequestParam String b) { return "x"; }\n${handlers}`,
    );
    expect((await attributeOf(source, "banner"))?.views).toEqual(["first", "second"]);
  });
});

describe("the links reach the Thymeleaf verdict", () => {
  const roots: string[] = [];
  afterEach(() => {
    for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
  });
  const scan = async (files: Record<string, string>) => {
    const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-views-")));
    roots.push(root);
    for (const [name, text] of Object.entries(files)) {
      mkdirSync(path.dirname(path.join(root, name)), { recursive: true });
      writeFileSync(path.join(root, name), text);
    }
    const output = await scanSourceCode(root);
    return output.findings.filter((finding) => finding.ruleId === "PG-XSS-004");
  };
  const page = (name: string): string => `<p th:utext="\${${name}}"></p>`;

  it("a constant view: the template of that view is medium, another view is only low", async () => {
    const found = await scan({
      "src/main/java/C.java": controller(
        'static final String PROFILE = "profile";\n@GetMapping("/b") String b(@RequestParam String bio, Model model) {\nmodel.addAttribute("bio", bio);\nreturn PROFILE;\n}',
      ),
      "src/main/resources/templates/profile.html": page("bio"),
      "src/main/resources/templates/other.html": page("bio"),
    });
    const profile = found.find((finding) => finding.location.path?.endsWith("profile.html"));
    const other = found.find((finding) => finding.location.path?.endsWith("other.html"));
    expect(profile).toMatchObject({ confidence: "medium", severity: "high" });
    expect(other?.confidence).toBe("low");
  });
  it("another attribute name on the linked view is not made request input", async () => {
    const found = await scan({
      "src/main/java/C.java": controller(
        '@GetMapping("/b") String b(@RequestParam String bio, Model model) {\nmodel.addAttribute("bio", bio);\nreturn "profile";\n}',
      ),
      "src/main/resources/templates/profile.html": page("title"),
    });
    expect(
      found.find((finding) => finding.location.path?.endsWith("profile.html"))?.confidence,
    ).toBe("low");
  });
  it("a flash attribute reaches the template of the redirect target", async () => {
    const found = await scan({
      "src/main/java/C.java": controller(
        '@PostMapping("/save") String save(@RequestParam String msg, RedirectAttributes ra) {\nra.addFlashAttribute("msg", msg);\nreturn "redirect:/thanks";\n}\n@GetMapping("/thanks") String thanks() { return "thanks"; }',
      ),
      "src/main/resources/templates/thanks.html": page("msg"),
    });
    expect(found.find((finding) => finding.location.path?.endsWith("thanks.html"))).toMatchObject({
      confidence: "medium",
    });
  });
  it("a @ModelAttribute attribute reaches every template of the controller", async () => {
    const found = await scan({
      "src/main/java/C.java": controller(
        '@ModelAttribute("banner") String banner(@RequestParam String b) { return b; }\n@GetMapping("/a") String a() { return "first"; }\n@GetMapping("/b") String b() { return "second"; }',
      ),
      "src/main/resources/templates/first.html": page("banner"),
      "src/main/resources/templates/second.html": page("banner"),
    });
    expect(found.filter((finding) => finding.confidence === "medium")).toHaveLength(2);
  });

  it("a partial source still gives a name-only finding on a view it does not list", () => {
    const model = new Map<string, ModelSource[]>([
      ["note", [{ path: "D.java", line: 3, views: ["a"], partial: true }]],
    ]);
    const other = analyzeThymeleaf('<p th:utext="${note}"></p>', "templates/b.html", model);
    expect(other.findings[0]?.confidence).toBe("low");
    expect(other.findings[0]?.evidence).toContain("D.java:3");
    const linked = analyzeThymeleaf('<p th:utext="${note}"></p>', "templates/a.html", model);
    expect(linked.findings[0]?.confidence).toBe("medium");
  });
});

describe("view resolution stays bounded", () => {
  it("many handlers and many flash attributes finish with the redirect lookups indexed", async () => {
    const handlers: string[] = [];
    for (let i = 0; i < 400; i += 1) {
      handlers.push(
        `@PostMapping("/save${i}") String save${i}(@RequestParam String m, RedirectAttributes ra) {\nra.addFlashAttribute("m${i}", m);\nreturn "redirect:/page${i}";\n}\n@GetMapping("/page${i}") String page${i}() { return "page${i}"; }`,
      );
    }
    const attributes = (await run(controller(handlers.join("\n")))).modelAttributes;
    expect(attributes).toHaveLength(400);
    expect(attributes[399]?.views).toEqual(["page399"]);
  });
  it("more views than the class limit are not listed: the attribute keeps the name-only match", async () => {
    const handlers: string[] = [];
    for (let i = 0; i < 520; i += 1) {
      handlers.push(`@GetMapping("/p${i}") String p${i}() { return "view${i}"; }`);
    }
    const source = controller(
      `@ModelAttribute("banner") String banner(@RequestParam String b) { return b; }\n${handlers.join("\n")}`,
    );
    const found = await attributeOf(source, "banner");
    expect(found?.views).toEqual([]);
    expect(found?.partial).toBe(true);
  });
});
