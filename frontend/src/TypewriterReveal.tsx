import { useScrollReveal } from "./useScrollReveal";

interface Props {
  text: string;
  className?: string;
  delayStep?: number; // ms between each letter
  as?: "p" | "h1" | "h2" | "span";
}

function TypewriterReveal({ text, className = "", delayStep = 18, as = "p" }: Props) {
  const { ref, visible } = useScrollReveal<HTMLElement>();
  const letters = text.split("");

  const Tag = as as any;

  return (
    <Tag ref={ref} className={`typewriter ${className}`}>
      {letters.map((char, i) => (
        <span
          key={i}
          className={`tw-letter ${visible ? "tw-visible" : ""}`}
          style={{ transitionDelay: `${i * delayStep}ms` }}
        >
          {char === " " ? "\u00A0" : char}
        </span>
      ))}
    </Tag>
  );
}

export default TypewriterReveal;