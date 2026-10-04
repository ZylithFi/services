import { loadConfig } from "./config.js";
import { createPaymasterServer } from "./server.js";
import { verifyPinnedPrivacyPoolClass } from "./starknetSubmitter.js";

const config = loadConfig();
await verifyPinnedPrivacyPoolClass(config);
const server = createPaymasterServer(config);

server.listen(config.port, config.bindHost, () => {
  console.log(
    `zylith-paymaster listening on http://${config.bindHost}:${config.port}/execute-outside`
  );
});
