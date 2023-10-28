import { sleep, check } from "k6";
import http from "k6/http";

export let options = {
  stages: [
    { duration: "15s", target: 1000 },
    { duration: "30s", target: 1000 },
    { duration: "15s", target: 0 },
  ],
};

export default function () {
  let res = http.get("http://localhost:8080");
  check(res, { "status was 200": (r) => r.status == 200 });
  sleep(1);
}
