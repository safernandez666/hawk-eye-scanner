# Poirot DSPM Dashboard - Next.js

Dashboard moderno para Hawk-Eye Scanner construido con **Next.js 14**, **shadcn/ui**, **Tailwind CSS** y **Recharts**.

![Tech Stack](https://img.shields.io/badge/Next.js-14-black?style=flat-square&logo=next.js)
![shadcn/ui](https://img.shields.io/badge/shadcn%2Fui-latest-black?style=flat-square)
![Tailwind](https://img.shields.io/badge/Tailwind-3.4-38B2AC?style=flat-square&logo=tailwind-css)

## ✨ Features

- 🎨 **UI Moderna** - Componentes shadcn/ui con Tailwind CSS
- 📊 **Visualizaciones** - Gráficos interactivos con Recharts
- 🌙 **Dark Mode** - Soporte completo claro/oscuro
- 📱 **Responsive** - Funciona en desktop y mobile
- ⚡ **Rendimiento** - Server Components y caching
- 🔌 **API Integration** - Conectado al backend Flask del proyecto

## 📁 Estructura

```
dashboard/frontend-next/
├── src/
│   ├── app/                 # Next.js App Router
│   │   ├── page.tsx         # Dashboard principal
│   │   ├── alerts/          # Página de alertas
│   │   ├── patterns/        # Patrones detectados
│   │   ├── timeline/        # Timeline de detecciones
│   │   ├── sources/         # Fuentes de datos
│   │   ├── cases/           # Casos TheHive
│   │   └── layout.tsx       # Layout principal
│   ├── components/
│   │   ├── ui/              # Componentes shadcn/ui
│   │   ├── sidebar.tsx      # Navegación lateral
│   │   ├── severity-badge.tsx
│   │   └── stats-card.tsx
│   ├── hooks/
│   │   └── use-api.ts       # Hooks para fetch de datos
│   ├── types/
│   │   └── index.ts         # TypeScript types
│   └── lib/
│       └── utils.ts         # Utilidades (cn, etc.)
├── package.json
├── tailwind.config.ts
└── next.config.mjs
```

## 🚀 Instalación

### Prerrequisitos

- Node.js 18+
- Backend Flask corriendo en `localhost:5001` (el `dev.py` del proyecto)

### Paso a paso

```bash
# 1. Navegar al directorio
cd dashboard/frontend-next

# 2. Instalar dependencias
npm install

# 3. Asegurarse que el backend Flask está corriendo
# En otra terminal, desde la raíz del proyecto:
python3 dashboard/dev.py

# 4. Iniciar el dashboard
npm run dev

# 5. Abrir en browser
open http://localhost:3000
```

## 🔌 Conexión con Backend

El dashboard se conecta automáticamente al API Flask que corre en `localhost:5001`. 

La configuración del proxy está en `next.config.mjs`:

```javascript
async rewrites() {
  return [
    {
      source: "/api/:path*",
      destination: "http://localhost:5001/api/:path*",
    },
  ];
}
```

## 📊 Páginas

| Página | Descripción | Ruta |
|--------|-------------|------|
| Dashboard | KPIs, gráficos de severidad/fuentes, alertas recientes | `/` |
| Alertas | Tabla completa con filtros y exportación CSV/JSON | `/alerts` |
| Patrones | Listado de patrones detectados con conteos | `/patterns` |
| Timeline | Gráfico de líneas con evolución de detecciones | `/timeline` |
| Fuentes | Fuentes configuradas con estado de conectividad | `/sources` |
| Casos | Casos de TheHive con sync | `/cases` |

## 🛠️ Scripts

```bash
npm run dev      # Desarrollo (localhost:3000)
npm run build    # Build de producción
npm run start    # Iniciar en producción
```

## 🎨 Componentes UI

Los componentes de shadcn/ui incluidos:

- `button` - Botones con variants
- `card` - Tarjetas de contenido
- `badge` - Badges de estado/severidad
- `table` - Tablas de datos
- `select` - Dropdowns de selección
- `input` - Campos de texto
- `tabs` - Navegación por tabs
- `tooltip` - Tooltips informativos
- `dropdown-menu` - Menús desplegables
- `separator` - Separadores visuales
- `skeleton` - Estados de carga

## 📝 Personalización

### Agregar una nueva página

1. Crear carpeta en `src/app/nueva-pagina/`
2. Crear `page.tsx` con el componente
3. Agregar item en `src/components/sidebar.tsx`

### Cambiar colores

Editar `tailwind.config.ts`:

```typescript
colors: {
  critical: { DEFAULT: "#dc2626", light: "#fee2e2" },
  high: { DEFAULT: "#ea580c", light: "#ffedd5" },
  // ...
}
```

## 🔗 Referencias

- [shadcn/ui](https://ui.shadcn.com/)
- [Next.js](https://nextjs.org/)
- [Tailwind CSS](https://tailwindcss.com/)
- [Recharts](https://recharts.org/)
