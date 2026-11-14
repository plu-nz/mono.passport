import { defineConfig } from 'wxt';
import identity from './identity.json';

export default defineConfig({
  manifest: {
    name: 'Passport',
    description: 'Acesse seu cofre Passport a partir do navegador.',
    key: identity.key,
    permissions: ['nativeMessaging', 'activeTab', 'scripting', 'storage'],
  },
});
