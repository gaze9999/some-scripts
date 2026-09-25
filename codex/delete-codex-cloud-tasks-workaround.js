/**
 * Codex Cloud Task 批次刪除 Workaround
 *
 * 用途:
 * 刪除 Codex Cloud 中目前無法透過 Codex CLI / Desktop UI
 * 正常永久刪除的 `task_e_...` Cloud tasks
 *
 * 已驗證環境:
 * - Windows
 * - Codex CLI 0.157.0
 * - ChatGPT Web
 * - 2026-09-26
 *
 * 已驗證 API:
 *
 * DELETE /backend-api/wham/tasks/{task_id}
 *
 * 已驗證成功條件:
 *
 * DELETE:
 * HTTP 200
 *
 * 再次 GET:
 * HTTP 404
 * {"detail":"Invalid task ID"}
 *
 * 注意:
 * - 此 endpoint 為 ChatGPT / Codex 內部 API
 * - 並非 OpenAI 公開 API
 * - 未來可能修改、移除或改變驗證方式
 * - Script 預設為 Dry Run
 * - 不會將 access token 寫入任何持久化儲存
 * - 請勿將 Access Token、Cookie、Session ID 寫入 Script
 * - 建議在 https://chatgpt.com 的 DevTools Console 執行
 *
 * 使用方式:
 *
 * 1. PowerShell 執行:
 *
 *    .\get-codex-cloud-task-ids.ps1
 *
 * 2. Script 會將:
 *
 *    const taskIds = [...]
 *
 *    自動複製到剪貼簿
 *
 * 3. 開啟:
 *
 *    https://chatgpt.com
 *
 * 4. F12 -> Console
 *
 * 5. 將 taskIds 貼到下方 TASK IDS 區域
 *
 * 6. 第一次保持:
 *
 *    MODE = 'dry-run'
 *
 * 7. 確認所有 Task ID 都正確
 *
 * 8. 改為:
 *
 *    MODE = 'delete'
 *
 * 9. 再執行整份 Script
 *
 * 10. 最後 PowerShell 執行:
 *
 *     codex cloud list
 *
 *     確認 Task 已全部消失
 */

// ============================================================
// 設定
// ============================================================

/**
 * 執行模式
 *
 * dry-run:
 * 只顯示準備刪除的 Task
 *
 * delete:
 * 執行真正 DELETE 並進行 GET 驗證
 *
 * @type {'dry-run' | 'delete'}
 */
const MODE = 'dry-run';

/**
 * 每次 request 之間等待時間
 *
 * 避免短時間對內部 API 送出大量 request
 *
 * @type {number}
 */
const REQUEST_INTERVAL_MS = 300;

/**
 * DELETE 完成後是否再次 GET 驗證 Task 已不存在
 *
 * 建議保持 true
 *
 * @type {boolean}
 */
const VERIFY_AFTER_DELETE = true;

// ============================================================
// TASK IDS
// ============================================================

/**
 * 從 PowerShell Script 輸出的 Array 貼到這裡
 *
 * @type {string[]}
 */
const taskIds = [
  // 'task_e_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
];

// ============================================================
// Types
// ============================================================

/**
 * 單筆刪除狀態
 *
 * @typedef {
 *   'deleted' |
 *   'alreadyDeleted' |
 *   'deleteFailed' |
 *   'verifyFailed' |
 *   'error'
 * } DeleteStatus
 */

/**
 * 單筆 Cloud Task 處理結果
 *
 * @typedef {Object} DeleteResult
 * @property {string} taskId Task ID
 * @property {DeleteStatus} status 處理結果
 * @property {number|null} deleteStatus DELETE HTTP Status
 * @property {number|null} verifyStatus 驗證 GET HTTP Status
 * @property {string} [message] 額外錯誤或狀態訊息
 */

// ============================================================
// Helpers
// ============================================================

/**
 * 暫停指定時間
 *
 * @param {number} ms 等待毫秒數
 * @returns {Promise<void>}
 */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * 驗證 Task ID 格式
 *
 * @param {string} taskId Task ID
 * @returns {boolean}
 */
function isValidTaskId(taskId) {
  return /^task_e_[0-9A-Za-z_-]+$/.test(taskId);
}

/**
 * 整理 Task ID 清單
 *
 * 功能:
 * - trim
 * - 排除空字串
 * - 驗證格式
 * - 去除重複 ID
 *
 * @param {string[]} ids 原始 Task ID
 * @returns {string[]}
 */
function normalizeTaskIds(ids) {
  const normalized = [];

  for (const value of ids) {
    if (typeof value !== 'string') {
      console.warn(
        '[SKIP] Task ID 不是 string',
        value,
      );

      continue;
    }

    const taskId = value.trim();

    if (!taskId) {
      continue;
    }

    if (!isValidTaskId(taskId)) {
      console.warn(
        `[SKIP] Task ID 格式不正確: ${taskId}`,
      );

      continue;
    }

    normalized.push(taskId);
  }

  return [...new Set(normalized)];
}

/**
 * 取得目前 ChatGPT session 的 Access Token
 *
 * Token 只保留在目前 JavaScript 記憶體中
 * 不會寫入 localStorage、sessionStorage 或其他持久化儲存
 *
 * @returns {Promise<string>}
 * @throws {Error} Session 或 Access Token 無法取得時
 */
async function getAccessToken() {
  const response = await fetch('/api/auth/session', {
    credentials: 'include',
  });

  if (!response.ok) {
    throw new Error(
      `取得 ChatGPT session 失敗: HTTP ${response.status}`,
    );
  }

  const session = await response.json();

  if (
    typeof session?.accessToken !== 'string' ||
    !session.accessToken
  ) {
    throw new Error(
      '目前 ChatGPT session 沒有 accessToken，請確認已正常登入',
    );
  }

  return session.accessToken;
}

/**
 * 查詢單一 Codex Cloud Task
 *
 * @param {string} taskId Cloud Task ID
 * @param {string} accessToken ChatGPT Access Token
 * @returns {Promise<Response>}
 */
function getTask(taskId, accessToken) {
  return fetch(
    `/backend-api/wham/tasks/${encodeURIComponent(taskId)}`,
    {
      method: 'GET',

      headers: {
        Authorization: `Bearer ${accessToken}`,
      },

      credentials: 'include',
    },
  );
}

/**
 * 永久刪除單一 Codex Cloud Task
 *
 * 使用未公開 ChatGPT internal API:
 *
 * DELETE /backend-api/wham/tasks/{task_id}
 *
 * @param {string} taskId Cloud Task ID
 * @param {string} accessToken ChatGPT Access Token
 * @returns {Promise<Response>}
 */
function deleteTask(taskId, accessToken) {
  return fetch(
    `/backend-api/wham/tasks/${encodeURIComponent(taskId)}`,
    {
      method: 'DELETE',

      headers: {
        Authorization: `Bearer ${accessToken}`,
      },

      credentials: 'include',
    },
  );
}

/**
 * 嘗試取得 HTTP Response Body
 *
 * 某些 API 錯誤可能沒有 Response Body
 * 因此失敗時回傳空字串
 *
 * @param {Response} response Fetch Response
 * @returns {Promise<string>}
 */
async function getResponseText(response) {
  try {
    return await response.text();
  }
  catch {
    return '';
  }
}

/**
 * 刪除並驗證單一 Codex Cloud Task
 *
 * 流程:
 *
 * 1. DELETE Task
 *
 * 2. 如果 DELETE 回傳 404:
 *    Task 原本已不存在
 *
 * 3. 如果 DELETE 為 2xx:
 *    再執行 GET
 *
 * 4. 如果 GET 回傳 404:
 *    確認 Task 已從 backend 移除
 *
 * @param {string} taskId Cloud Task ID
 * @param {string} accessToken ChatGPT Access Token
 * @returns {Promise<DeleteResult>}
 */
async function deleteAndVerifyTask(
  taskId,
  accessToken,
) {
  try {
    const deleteResponse = await deleteTask(
      taskId,
      accessToken,
    );

    if (deleteResponse.status === 404) {
      return {
        taskId,
        status: 'alreadyDeleted',
        deleteStatus: 404,
        verifyStatus: null,
        message: 'Task 原本已不存在',
      };
    }

    if (!deleteResponse.ok) {
      return {
        taskId,
        status: 'deleteFailed',
        deleteStatus: deleteResponse.status,
        verifyStatus: null,
        message: await getResponseText(
          deleteResponse,
        ),
      };
    }

    if (!VERIFY_AFTER_DELETE) {
      return {
        taskId,
        status: 'deleted',
        deleteStatus: deleteResponse.status,
        verifyStatus: null,
      };
    }

    const verifyResponse = await getTask(
      taskId,
      accessToken,
    );

    if (verifyResponse.status === 404) {
      return {
        taskId,
        status: 'deleted',
        deleteStatus: deleteResponse.status,
        verifyStatus: 404,
      };
    }

    return {
      taskId,
      status: 'verifyFailed',
      deleteStatus: deleteResponse.status,
      verifyStatus: verifyResponse.status,
      message:
        'DELETE 已成功，但重新 GET 時 Task 仍然存在',
    };
  }
  catch (error) {
    return {
      taskId,
      status: 'error',
      deleteStatus: null,
      verifyStatus: null,
      message:
        error instanceof Error
          ? error.message
          : String(error),
    };
  }
}

/**
 * 顯示 Dry Run Task 清單
 *
 * @param {string[]} ids Task ID 清單
 * @returns {void}
 */
function printDryRun(ids) {
  console.group(
    `[Codex Cloud] DRY RUN - ${ids.length} Tasks`,
  );

  ids.forEach((taskId, index) => {
    console.log(
      `[${index + 1}/${ids.length}] ${taskId}`,
    );
  });

  console.groupEnd();

  console.table(
    ids.map((taskId, index) => ({
      index: index + 1,
      taskId,
    })),
  );
}

/**
 * 顯示單筆刪除結果
 *
 * @param {DeleteResult} result 刪除結果
 * @returns {void}
 */
function printDeleteResult(result) {
  switch (result.status) {
    case 'deleted':
      console.log(
        `[DELETED + VERIFIED] ${result.taskId}`,
      );

      break;

    case 'alreadyDeleted':
      console.info(
        `[ALREADY DELETED] ${result.taskId}`,
      );

      break;

    case 'deleteFailed':
      console.error(
        `[DELETE FAILED ${result.deleteStatus}] ${result.taskId}`,
        result.message ?? '',
      );

      break;

    case 'verifyFailed':
      console.warn(
        `[VERIFY FAILED ${result.verifyStatus}] ${result.taskId}`,
        result.message ?? '',
      );

      break;

    case 'error':
      console.error(
        `[ERROR] ${result.taskId}`,
        result.message ?? '',
      );

      break;
  }
}

/**
 * 顯示全部處理結果
 *
 * @param {DeleteResult[]} results 所有刪除結果
 * @returns {void}
 */
function printSummary(results) {
  const summary = {
    total: results.length,
    deleted: 0,
    alreadyDeleted: 0,
    deleteFailed: 0,
    verifyFailed: 0,
    error: 0,
  };

  for (const result of results) {
    summary[result.status]++;
  }

  console.group('[Codex Cloud] 執行結果');

  console.table(summary);

  const failed = results.filter(
    result =>
      result.status === 'deleteFailed' ||
      result.status === 'verifyFailed' ||
      result.status === 'error',
  );

  if (failed.length === 0) {
    console.log(
      '所有 Task 均已刪除或原本已不存在',
    );
  }
  else {
    console.warn(
      `${failed.length} 筆 Task 尚未完整刪除`,
    );

    console.table(
      failed.map(result => ({
        taskId: result.taskId,
        status: result.status,
        deleteStatus: result.deleteStatus,
        verifyStatus: result.verifyStatus,
        message: result.message ?? '',
      })),
    );
  }

  console.groupEnd();
}

// ============================================================
// Main
// ============================================================

/**
 * Codex Cloud Task Cleanup 主流程
 *
 * @returns {Promise<void>}
 */
async function main() {
  if (location.hostname !== 'chatgpt.com') {
    throw new Error(
      '請在 https://chatgpt.com 的 DevTools Console 執行',
    );
  }

  if (
    MODE !== 'dry-run' &&
    MODE !== 'delete'
  ) {
    throw new Error(
      `無效 MODE: ${MODE}`,
    );
  }

  const ids = normalizeTaskIds(taskIds);

  if (ids.length === 0) {
    throw new Error(
      '沒有有效的 task_e_... Task ID',
    );
  }

  console.log(
    `[Codex Cloud] 準備處理 ${ids.length} 筆 Task`,
  );

  if (MODE === 'dry-run') {
    printDryRun(ids);

    console.info(
      "確認無誤後將 MODE 改成 'delete' 再重新執行",
    );

    return;
  }

  console.warn(
    `[Codex Cloud] 即將永久刪除 ${ids.length} 筆 Cloud Task`,
  );

  const accessToken = await getAccessToken();

  /** @type {DeleteResult[]} */
  const results = [];

  for (
    let index = 0;
    index < ids.length;
    index++
  ) {
    const taskId = ids[index];

    console.log(
      `[${index + 1}/${ids.length}] DELETE ${taskId}`,
    );

    const result = await deleteAndVerifyTask(
      taskId,
      accessToken,
    );

    results.push(result);

    printDeleteResult(result);

    if (index < ids.length - 1) {
      await sleep(REQUEST_INTERVAL_MS);
    }
  }

  printSummary(results);

  console.info(
    '完成後請執行 `codex cloud list` 再確認一次',
  );
}

await main();