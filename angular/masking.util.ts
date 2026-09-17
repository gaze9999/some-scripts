/**
 * Data Masking Utility
 */
export class MaskingUtil {

  /**
   * 客戶姓名隱碼
   * • 長度 <= 7 字：保留首尾字元，中間字元以 O 遮蔽
   * • 長度 > 7 字：保留前 2 碼與後 2 碼，中間以 O 遮蔽
   */
  static maskName(name: string): string {
    if (!name) return '';
    const str = name.trim();
    const len = str.length;
    if (len <= 1) return str;
    if (len === 2) return str.charAt(0) + 'O';
    if (len <= 7) {
      const middleCount = len - 2;
      return str.charAt(0) + 'O'.repeat(middleCount) + str.charAt(len - 1);
    } else {
      const firstTwo = str.substring(0, 2);
      const lastTwo = str.substring(len - 2);
      const middleCount = len - 4;
      return firstTwo + 'O'.repeat(middleCount) + lastTwo;
    }
  }

  /**
   * 身分證字號 / 統編隱碼
   * 保留前 4 碼與後 3 碼，中間以 *** 遮蔽
   */
  static maskId(id: string): string {
    if (!id) return '';
    const str = id.trim();
    const len = str.length;
    if (len <= 7) {
      if (len <= 4) return str;
      return str.substring(0, 2) + '***' + str.substring(len - 2);
    }
    const firstFour = str.substring(0, 4);
    const lastThree = str.substring(len - 3);
    return `${firstFour}***${lastThree}`;
  }

  /**
   * 銀行帳號隱碼
   * 補零至位數後，遮蔽第 6~7 碼 (**)
   */
  static maskAccount(acct: string): string {
    if (!acct) return '';
    let str = acct.trim();
    if (str.length < 14) {
      str = str.padStart(14, '0');
    }
    if (str.length >= 7) {
      return str.substring(0, 5) + '**' + str.substring(7);
    }
    return str;
  }

  /**
   * 信用卡卡號隱碼
   * 顯示前 6 碼及後 4 碼，其餘以 * 遮蔽
   */
  static maskCreditCard(cc: string): string {
    if (!cc) return '';
    const raw = cc.replace(/\s+/g, '');
    if (raw.length < 10) return cc;
    const firstSix = raw.substring(0, 6);
    const lastFour = raw.substring(raw.length - 4);
    const middleLen = raw.length - 10;
    return `${firstSix}${'*'.repeat(middleLen)}${lastFour}`;
  }

  /**
   * 通訊地址隱碼
   * 保留縣市與行政區 (前6字)，後續地址：
   * • <3 碼：全遮 ***
   * • 3~19 碼：遮前 3 碼 ***
   * • >19 碼：遮前 6 碼 ******
   */
  static maskAddress(addr: string): string {
    if (!addr) return '';
    const str = addr.trim();
    if (str.length <= 6) return str;
    const prefix = str.substring(0, 6);
    const rest = str.substring(6);
    const restLen = rest.length;

    if (restLen < 3) {
      return prefix + '***';
    } else if (restLen <= 19) {
      return prefix + '***' + rest.substring(3);
    } else {
      return prefix + '******' + rest.substring(6);
    }
  }

  /**
   * 電話號碼隱碼
   * 隱碼第 7、8 碼 (0933556778 -> 093355**78)
   */
  static maskPhone(phone: string): string {
    if (!phone) return '';
    const digits = phone.replace(/\s+/g, '');
    if (digits.length >= 8) {
      return digits.substring(0, 6) + '**' + digits.substring(8);
    }
    return phone;
  }

  /**
   * 電子郵件隱碼
   * 僅顯示 @ 前 1 碼與完整網域名稱，其餘以 * 遮蔽 (user.name@email.com -> *********e@email.com)
   */
  static maskEmail(email: string): string {
    if (!email || !email.includes('@')) return email;
    const parts = email.split('@');
    const local = parts[0];
    const domain = parts[1];
    if (local.length <= 1) {
      return `${local}@${domain}`;
    }
    const lastChar = local.charAt(local.length - 1);
    const maskedLocal = '*'.repeat(local.length - 1) + lastChar;
    return `${maskedLocal}@${domain}`;
  }
}
