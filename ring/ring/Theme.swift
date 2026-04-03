import SwiftUI

enum Theme {
    // Primary palette (derived from crypto-wallet)
    static let lavender = Color(red: 216/255, green: 200/255, blue: 240/255)
    static let amber = Color(red: 232/255, green: 205/255, blue: 122/255)
    static let lime = Color(red: 212/255, green: 245/255, blue: 66/255)

    // App accent — muted purple, visible in both light and dark mode
    static let accent = Color(red: 140/255, green: 100/255, blue: 200/255)

    // Status colors
    static let connected = Color(red: 120/255, green: 210/255, blue: 90/255)
    static let transitioning = amber

    // Threat severity colors
    static let threatRed = Color(red: 220/255, green: 60/255, blue: 60/255)
    static let threatOrange = Color(red: 235/255, green: 150/255, blue: 50/255)
    static let threatYellow = Color(red: 230/255, green: 200/255, blue: 60/255)

    // Card system (crypto-wallet layout pattern)
    static let cardBackground = Color(.secondarySystemGroupedBackground)
    static let pageBackground = Color(.systemGroupedBackground)
    static let cardRadius: CGFloat = 16
    static let cardShadow = Color.black.opacity(0.04)

    // Category colors (shared across views)
    static let categoryColors: [String: Color] = [
        "social_media": .blue,
        "shopping": .orange,
        "entertainment": .purple,
        "news": .red,
        "search": .green,
        "communication": .teal,
        "finance": .mint,
        "productivity": .indigo,
        "gaming": .pink,
        "education": .cyan,
        "food_delivery": .yellow,
        "health": Color(red: 0.9, green: 0.3, blue: 0.3),
        "travel": Color(red: 0.2, green: 0.6, blue: 0.9),
        "technology": .gray,
        "ai_tools": Color(red: 0.4, green: 0.3, blue: 0.9),
        "dating": Color(red: 0.95, green: 0.3, blue: 0.5),
        "sports": Color(red: 0.1, green: 0.7, blue: 0.4),
        "weather": Color(red: 0.3, green: 0.7, blue: 0.9),
        "government": Color(red: 0.2, green: 0.4, blue: 0.7),
        "transportation": Color(red: 0.95, green: 0.6, blue: 0.1),
        "uncategorized": Color(.systemGray3),
    ]

    static func colorForDomain(_ domain: String) -> Color {
        if let cat = CategoriesService.shared.categorize(domain) {
            return categoryColors[cat.key] ?? accent
        }
        return accent
    }
}

// MARK: - Card View Modifier

struct CardStyle: ViewModifier {
    func body(content: Content) -> some View {
        content
            .background(Theme.cardBackground)
            .cornerRadius(Theme.cardRadius)
            .shadow(color: Theme.cardShadow, radius: 8, y: 2)
    }
}

extension View {
    func cardStyle() -> some View {
        modifier(CardStyle())
    }
}

// MARK: - Section Header

struct SectionHeader: View {
    let title: String
    var count: Int? = nil

    var body: some View {
        HStack(spacing: 8) {
            Text(title)
                .font(.title3.weight(.semibold))
                .tracking(-0.3)

            if let count {
                Text("\(count)")
                    .font(.caption.weight(.bold))
                    .foregroundColor(.white)
                    .frame(minWidth: 22, minHeight: 22)
                    .padding(.horizontal, count > 99 ? 6 : 0)
                    .background(Theme.accent.opacity(0.7))
                    .clipShape(Capsule())
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.top, 8)
    }
}
