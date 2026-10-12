import { render } from "solid-js/web";
import App from "./App";
import "./styles.css";

const root = document.getElementById("root");
if (!root) {
  throw new Error("Deepsand could not find its #root element to mount into.");
}

render(() => <App />, root);
