// Run with Playwright available to Node: node scripts/test-voice-player.cjs
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const { chromium } = require("playwright");

(async () => {
  const browser = await chromium.launch();
  const root = path.resolve(__dirname, "../pasztar/frontend");
  try {
    const context = await browser.newContext();
    // Serve the real frontend files without a backend or a listening test server.
    await context.route("http://localhost/**", async (route) => {
      const pathname = new URL(route.request().url()).pathname;
      const filename = path.resolve(
        root,
        `.${pathname === "/" ? "/index.html" : pathname}`,
      );
      assert.ok(filename.startsWith(root + path.sep));
      let body = await fs.readFile(filename);
      const extension = path.extname(filename);
      if (extension === ".html") {
        body = Buffer.from(
          body
            .toString()
            .replace(
              '<script type="module" src="/static/js/app.js"></script>',
              "",
            ),
        );
      }
      await route.fulfill({
        body,
        contentType: {
          ".html": "text/html",
          ".css": "text/css",
          ".js": "text/javascript",
          ".png": "image/png",
        }[extension],
      });
    });
    await context.addInitScript(() =>
      localStorage.setItem("pasztar.identity", "{}"),
    );
    const page = await context.newPage();
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    await page.goto("http://localhost/");
    await page.evaluate(async () => {
      const { renderMessageBody } = await import("/static/js/messages.js");
      const { state } = await import("/static/js/context.js");
      window.voiceState = state;
      // A real stereo WAV: silence first, then changing amplitude in channel two.
      function wav(silent = false, seconds = 4) {
        const frames = Math.round(8000 * seconds);
        const data = new ArrayBuffer(44 + frames * 4);
        const view = new DataView(data);
        for (const [offset, text] of [
          [0, "RIFF"],
          [8, "WAVE"],
          [12, "fmt "],
          [36, "data"],
        ]) {
          [...text].forEach((char, index) =>
            view.setUint8(offset + index, char.charCodeAt(0)),
          );
        }
        for (const [offset, value] of [
          [4, data.byteLength - 8],
          [16, 16],
          [24, 8000],
          [28, 32000],
          [40, frames * 4],
        ])
          view.setUint32(offset, value, true);
        for (const [offset, value] of [
          [20, 1],
          [22, 2],
          [32, 4],
          [34, 16],
        ])
          view.setUint16(offset, value, true);
        for (let index = 0; index < frames; index += 1) {
          const amplitude =
            silent || index < frames / 4
              ? 0
              : 0.2 + 0.7 * Math.abs(Math.sin(index / 3000));
          view.setInt16(
            46 + index * 4,
            Math.round(Math.sin(index / 8) * amplitude * 32767),
            true,
          );
        }
        return data;
      }
      const messages = document.querySelector("#messages");
      messages.replaceChildren();
      document.querySelector(".shell").classList.add("chat-open");
      for (const [id, kind, data] of [
        ["incoming", "incoming", wav()],
        ["own", "own", wav(true)],
        ["short", "incoming", wav(false, 0.05)],
        ["invalid", "incoming", new ArrayBuffer(5)],
      ]) {
        const article = document.createElement("article");
        article.id = id;
        article.className = `message ${kind}`;
        const content = document.createElement("div");
        content.className = "message-content";
        content.append(
          await renderMessageBody(
            {},
            { kind: "voice", data, durationMs: 4000 },
          ),
        );
        article.append(content);
        messages.append(article);
      }
    });

    const voice = page.locator("#incoming");
    const button = voice.locator(".voice-play");
    const seek = voice.locator(".voice-seek");
    assert.equal(await voice.locator("button").count(), 1);
    assert.equal(await voice.locator(".voice-time").textContent(), "0:04");
    assert.match(
      await page.locator("#invalid").textContent(),
      /unable to play/,
    );
    const heights = await page.locator(".voice-waveform").evaluateAll((nodes) =>
      nodes.map((node) => {
        const svg = decodeURIComponent(
          node.style.getPropertyValue("--waveform-mask").split(",")[1],
        );
        return [...svg.matchAll(/v([\d.]+)/g)].map((match) => Number(match[1]));
      }),
    );
    assert.equal(heights[0].length, 48);
    assert.equal(Math.min(...heights[0]), 3);
    assert.equal(Math.max(...heights[0]), 28);
    assert.ok(
      new Set(heights[0]).size > 10,
      "waveform reflects channel-two audio",
    );
    assert.ok(
      heights[1].every((height) => height === 3),
      "silence stays flat",
    );
    assert.ok(
      heights[2].every(Number.isFinite),
      "very short clips render safely",
    );

    await button.click();
    await page.waitForFunction(
      () => Number(document.querySelector("#incoming .voice-seek").value) > 0.1,
    );
    assert.equal(
      await button.getAttribute("aria-label"),
      "Pause voice message",
    );
    assert.equal(await voice.locator(".voice-time").textContent(), "0:00");
    await button.click();
    const paused = await seek.inputValue();
    await page.waitForTimeout(150);
    assert.equal(await seek.inputValue(), paused);
    await seek.focus();
    await seek.press("Home");
    await seek.press("ArrowRight");
    assert.equal(await seek.inputValue(), "0.01");
    assert.equal(
      await voice
        .locator(".voice-waveform")
        .evaluate((node) => getComputedStyle(node).outlineStyle),
      "solid",
    );
    await seek.press("End");
    assert.equal(await seek.inputValue(), "4");
    await button.click();
    await page.waitForFunction(
      () => Number(document.querySelector("#incoming .voice-seek").value) < 1,
    );
    const box = await seek.boundingBox();
    await page.mouse.move(box.x + box.width * 0.5, box.y + box.height / 2);
    await page.mouse.down();
    await page.mouse.move(box.x + box.width * 0.75, box.y + box.height / 2, {
      steps: 6,
    });
    await page.mouse.up();
    assert.ok(Number(await seek.inputValue()) > 2.5);
    assert.equal(
      await button.getAttribute("aria-label"),
      "Pause voice message",
    );
    await page.waitForFunction(
      () =>
        document
          .querySelector("#incoming .voice-play")
          .getAttribute("aria-label") === "Play voice message",
    );
    assert.equal(await seek.inputValue(), "0");
    assert.equal(await voice.locator(".voice-time").textContent(), "0:04");

    // A delayed resume must not revive a paused player or start overlapping sources.
    await page.evaluate(async () => {
      const audio = window.voiceState.audioContext;
      const resume = audio.resume.bind(audio);
      const createSource = audio.createBufferSource.bind(audio);
      let release;
      let starts = 0;
      audio.resume = () =>
        new Promise((resolve) => {
          release = resolve;
        });
      audio.createBufferSource = () => {
        starts += 1;
        return createSource();
      };
      const play = document.querySelector("#incoming .voice-play");
      play.click();
      play.click();
      release();
      await Promise.resolve();
      if (starts !== 0)
        throw new Error("Paused playback restarted after resume");
      play.click();
      const seek = document.querySelector("#incoming .voice-seek");
      for (const value of [1, 2, 3]) {
        const previousRelease = release;
        seek.value = value;
        seek.dispatchEvent(new Event("input"));
        previousRelease();
      }
      release();
      await Promise.resolve();
      if (starts !== 1)
        throw new Error("Rapid seeking started overlapping sources");
      window.voiceState.voiceStops.forEach((stop) => stop());
      audio.resume = resume;
      audio.createBufferSource = createSource;
    });

    for (const width of [1280, 390, 320]) {
      await page.setViewportSize({ width, height: 800 });
      const fits = await voice.evaluate((node) => {
        const content = node
          .querySelector(".message-content")
          .getBoundingClientRect();
        const player = node
          .querySelector(".voice-player")
          .getBoundingClientRect();
        const waveform = node
          .querySelector(".voice-waveform")
          .getBoundingClientRect();
        return player.right <= content.right + 1 && waveform.width >= 60;
      });
      assert.ok(fits, `voice controls fit at ${width}px`);
    }
    // Touch a real range control on the existing page via Chromium's touch input.
    const session = await context.newCDPSession(page);
    const touchBox = await seek.boundingBox();
    await session.send("Input.dispatchTouchEvent", {
      type: "touchStart",
      touchPoints: [
        {
          x: touchBox.x + touchBox.width / 2,
          y: touchBox.y + touchBox.height / 2,
        },
      ],
    });
    await session.send("Input.dispatchTouchEvent", {
      type: "touchEnd",
      touchPoints: [],
    });
    assert.ok(Math.abs(Number(await seek.inputValue()) - 2) < 0.3);
    await page.evaluate(() =>
      window.voiceState.voiceStops.forEach((stop) => stop()),
    );
    assert.deepEqual(errors, []);
    if (process.env.VOICE_SCREENSHOT) {
      await page.setViewportSize({ width: 1000, height: 700 });
      await page
        .locator("#messages")
        .screenshot({ path: process.env.VOICE_SCREENSHOT });
    }
    console.log(
      "PASS: real waveform, silence, short/invalid clips, playback, pause, seeking, keyboard focus, touch, cleanup, and responsive layout.",
    );
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
