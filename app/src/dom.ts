// A tiny DOM builder: h("button", { onclick }, "text").
type Child = Node | string | number | null | undefined | false | Child[];
type Attrs = Record<string, unknown>;

export function h<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Attrs = {}, ...children: Child[]): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (name.startsWith("on") && typeof value === "function") {
      element.addEventListener(name.slice(2), value as EventListener);
    } else if (name === "class") {
      element.className = String(value);
    } else if (name === "dataset" && typeof value === "object") {
      Object.assign(element.dataset, value);
    } else if (name in element && typeof value !== "string") {
      (element as unknown as Record<string, unknown>)[name] = value;
    } else if (name === "value" || name === "checked" || name === "disabled") {
      (element as unknown as Record<string, unknown>)[name] = value;
    } else {
      element.setAttribute(name, value === true ? "" : String(value));
    }
  }
  append(element, children);
  return element;
}

function append(parent: Node, children: Child[]): void {
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    if (Array.isArray(child)) append(parent, child);
    else parent.appendChild(typeof child === "object" ? child : document.createTextNode(String(child)));
  }
}

/** Replace an element's children. */
export function fill(parent: Element, ...children: Child[]): void {
  parent.replaceChildren();
  append(parent, children);
}

/** A labelled form field. */
export function field(label: string, control: HTMLElement, extra?: Child): HTMLLabelElement {
  return h("label", { class: "field" }, h("span", { class: "field-label" }, label), control, extra);
}

/** Ask a yes/no question in an in-page dialog (no OS dialog permission needed). */
export function confirmDialog(text: string, yes: string, no: string): Promise<boolean> {
  return new Promise((resolve) => {
    const dialog = h("dialog", { class: "modal", "data-testid": "confirm-dialog" });
    const done = (value: boolean) => {
      dialog.close();
      dialog.remove();
      resolve(value);
    };
    fill(
      dialog,
      h("p", { class: "modal-text" }, text),
      h(
        "div",
        { class: "row end" },
        h("button", { type: "button", class: "secondary", onclick: () => done(false), "data-testid": "confirm-no" }, no),
        h("button", { type: "button", onclick: () => done(true), "data-testid": "confirm-yes" }, yes),
      ),
    );
    dialog.addEventListener("cancel", (event) => {
      event.preventDefault();
      done(false);
    });
    document.body.appendChild(dialog);
    if (typeof dialog.showModal === "function") dialog.showModal();
    else dialog.setAttribute("open", "");
  });
}
