// corpus: expect=PG-XSS-002
import React from "react";

export function Snippet({ snippet }) {
  return React.createElement("div", { className: "snippet", dangerouslySetInnerHTML: { __html: snippet } });
}
