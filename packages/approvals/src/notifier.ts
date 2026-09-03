export interface NotifierOptions {
    readonly loopbackBaseUrl: string;
    readonly discordWebhookUrl?: string;
}

export class Notifier {
    constructor(private options: NotifierOptions) {}

    public async notify(approvalId: string, approveToken: string, denyToken: string, details: Record<string, unknown>): Promise<void> {
        const approveUrl = new URL(`/approve/${approvalId}?token=${approveToken}`, this.options.loopbackBaseUrl).toString();
        const denyUrl = new URL(`/deny/${approvalId}?token=${denyToken}`, this.options.loopbackBaseUrl).toString();
        
        const messageText = `[SENTINEL APPROVAL REQUIRED]
ID: ${approvalId}
Agent: ${details.agentId}
Method: ${details.method}
Target: ${details.qualifiedName}
Approve: ${approveUrl}
Deny: ${denyUrl}
`;
        
        // 1. Always log to stdout (per M5 requirements)
        process.stdout.write(messageText + '\n');

        // 2. Optionally send to Discord if configured
        if (this.options.discordWebhookUrl) {
            try {
                await fetch(this.options.discordWebhookUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        content: `🚨 **Sentinel Approval Required**\n\n**Agent:** ${details.agentId}\n**Method:** ${details.method}\n**Target:** ${details.qualifiedName}\n\n[✅ Approve Request](${approveUrl})\n[❌ Deny Request](${denyUrl})`
                    })
                });
            } catch (err) {
                // If Discord fails, we at least have stdout. Log the failure.
                process.stderr.write(`Failed to send Discord webhook for approval ${approvalId}: ${err}\n`);
            }
        }
    }
}
