import type { Metadata } from "next";
import "./styles.css";
export const metadata: Metadata = { title: "Satellite Intelligence Platform" };
export default function Layout({ children }: { children: React.ReactNode }) { return <html lang="en"><body>{children}</body></html>; }
