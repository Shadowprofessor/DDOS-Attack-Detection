import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Markdown } from "./Markdown";

describe("Markdown renderer", () => {
  it("renders a table, heading, list and code block as real elements", () => {
    const src = "## Overview\n- point one\n\n| A | B |\n|---|---|\n| 1 | 2 |\n\n```\niptables -L\n```";
    const { container } = render(<Markdown source={src} />);
    expect(container.querySelector("table")).toBeTruthy();
    expect(container.querySelectorAll("td")).toHaveLength(2);
    expect(container.querySelector("ul li")?.textContent).toBe("point one");
    expect(container.querySelector("pre code")?.textContent).toBe("iptables -L");
    expect(container.querySelector(".md-h")?.textContent).toBe("Overview");
  });

  it("renders HTML in the model output as literal text, never as DOM (no injection)", () => {
    const { container } = render(<Markdown source={"before <img src=x onerror=alert(1)> <script>alert(2)</script> after"} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
    expect(container.textContent).toContain("<img src=x onerror=alert(1)>");
    expect(container.textContent).toContain("<script>alert(2)</script>");
  });

  it("renders inline code and bold inside a paragraph", () => {
    const { container } = render(<Markdown source={"block `10.99.0.10` at **100%**"} />);
    expect(container.querySelector("code")?.textContent).toBe("10.99.0.10");
    expect(container.querySelector("strong")?.textContent).toBe("100%");
  });
});
