import { Resend } from "resend";

const resend = new Resend(process.env.RESEND_API_KEY);

export const sendOtpEmail = async (toEmail: string, otpCode: string) => {
  const html = `
  <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 24px;">
    <div style=" padding: 32px; text-align: center;">
      
      <h2 style="margin: 0 0 8px; color: #1a1a1a; font-size: 20px;">
        Account Verification
      </h2>

      <p style="color: #555555; font-size: 14px; line-height: 22px; margin: 8px 0 24px;">
        Use the code below to verify your GFG RGIPT account.
      </p>

      <div style="background-color: #f5f5f5; border-radius: 6px; padding: 16px; margin-bottom: 20px;">
        <span style="font-size: 28px; font-weight: bold; letter-spacing: 6px; color: #1a1a1a;">
          ${otpCode}
        </span>
      </div>

      <p style="color: #888888; font-size: 13px; margin: 0;">
        This code is valid for 10 minutes.<br/>
        Do not share it with anyone.
      </p>

    </div>

    <p style="text-align: center; color: #aaaaaa; font-size: 12px; margin-top: 20px;">
      RGIPT GFG Student Chapter
    </p>
  </div>
  `;

  await resend.emails.send({
    from: process.env.EMAIL_FROM as string,
    to: toEmail,
    subject: "GFG RGIPT Verification Code",
    html,
  });
};