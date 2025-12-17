export type BackupCodesDisplayProps = {
  /**
   * Plaintext codes. Display once; do not store.
   */
  codes: string[];
};

export function BackupCodesDisplay(props: BackupCodesDisplayProps) {
  return (
    <div>
      <p>
        Save these backup codes somewhere safe. They will be shown only once. Each code can be used
        once.
      </p>
      <pre>{props.codes.join('\n')}</pre>
    </div>
  );
}
