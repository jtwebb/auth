import { describe, expect, it } from 'vitest';
import { renderToString } from 'react-dom/server';
import * as React from 'react';
import { BackupCodesDisplay, LoginForm } from '../../src/react/index.js';

describe('react/components', () => {
  it('renders LoginForm', () => {
    const html = renderToString(<LoginForm onSubmit={() => undefined} />);
    expect(html).toContain('Identifier');
    expect(html).toContain('Password');
  });

  it('renders BackupCodesDisplay', () => {
    const html = renderToString(<BackupCodesDisplay codes={['AAAAA-BBBBB', 'CCCCC-DDDDD']} />);
    expect(html).toContain('AAAAA-BBBBB');
  });
});
